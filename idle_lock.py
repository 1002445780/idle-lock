# -*- coding: utf-8 -*-
"""
挂机锁 IdleLock — 高颜值 Windows 挂机锁屏工具
=============================================
离开电脑时一键锁定屏幕:全屏置顶 + 毛玻璃极光界面 + 密码解锁。

用法:
    python idle_lock.py              # 立即锁定
    python idle_lock.py --idle 30    # 系统空闲 30 分钟后自动锁定
    python idle_lock.py --preview    # 预览模式(窗口化,不锁定键鼠,仅体验界面)
    python idle_lock.py --selftest   # 环境自检

依赖: pip install pywebview   (使用系统自带 WebView2 内核)
"""
import argparse
import base64
import ctypes
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path

APP_NAME = "IdleLock"
CONFIG_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / APP_NAME
CONFIG_FILE = CONFIG_DIR / "config.json"
UI_FILE = Path(__file__).resolve().parent / "ui" / "index.html"

PBKDF2_ITERS = 200_000
MAX_ATTEMPTS = 5          # 连续错误次数上限
COOLDOWN_SECONDS = 30     # 触发冷却时间

# ----------------------------------------------------------------------------
# Win32 API
# ----------------------------------------------------------------------------
_user32 = ctypes.WinDLL("user32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_SYSKEYDOWN = 0x0104
WM_SYSKEYUP = 0x0105
WM_QUIT = 0x0012

VK_TAB = 0x09
VK_ESCAPE = 0x1B
VK_F4 = 0x73
VK_F12 = 0x7B
VK_LWIN = 0x5B
VK_RWIN = 0x5C
VK_MENU = 0x12
VK_CONTROL = 0x11

LLKHF_ALTDOWN = 0x20

# 输入法控制(锁定时禁用 IME,防止按键被组字拦截)
_imm32 = ctypes.WinDLL("imm32")
_imm32.ImmAssociateContextEx.argtypes = [wintypes.HWND, wintypes.HANDLE, wintypes.DWORD]
_imm32.ImmAssociateContextEx.restype = wintypes.BOOL
_imm32.ImmAssociateContext.argtypes = [wintypes.HWND, wintypes.HANDLE]
_imm32.ImmAssociateContext.restype = wintypes.HANDLE
IACE_CHILDREN = 0x0001
IACE_DEFAULT = 0x0010
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
_user32.EnumChildWindows.argtypes = [wintypes.HWND, WNDENUMPROC, wintypes.LPARAM]
_user32.EnumChildWindows.restype = wintypes.BOOL
_user32.CallNextHookEx.argtypes = [
    wintypes.HHOOK, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM,
]
_user32.CallNextHookEx.restype = wintypes.LPARAM


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class RECT(ctypes.Structure):
    _fields_ = [
        ("left", wintypes.LONG),
        ("top", wintypes.LONG),
        ("right", wintypes.LONG),
        ("bottom", wintypes.LONG),
    ]


class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]


class SYSTEM_POWER_STATUS(ctypes.Structure):
    _fields_ = [
        ("ACLineStatus", ctypes.c_byte),
        ("BatteryFlag", ctypes.c_byte),
        ("BatteryLifePercent", ctypes.c_byte),
        ("Reserved1", ctypes.c_byte),
        ("BatteryLifeTime", wintypes.DWORD),
        ("BatteryFullLifeTime", wintypes.DWORD),
    ]


HOOKPROC = ctypes.WINFUNCTYPE(
    wintypes.LPARAM, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM
)


def system_idle_seconds() -> float:
    """距上次键鼠输入的秒数。"""
    info = LASTINPUTINFO()
    info.cbSize = ctypes.sizeof(info)
    if _user32.GetLastInputInfo(ctypes.byref(info)):
        return max(0.0, (_kernel32.GetTickCount() - info.dwTime) / 1000.0)
    return 0.0


def get_battery() -> dict:
    """电池电量与充电状态(台式机返回 unknown)。"""
    ps = SYSTEM_POWER_STATUS()
    if not _kernel32.GetSystemPowerStatus(ctypes.byref(ps)):
        return {"percent": None, "charging": False}
    pct = ps.BatteryLifePercent
    if pct == 255 or pct > 100:
        pct = None
    return {"percent": pct, "charging": bool(ps.ACLineStatus == 1)}


def set_window_ime(window, enable: bool) -> bool:
    """启用/禁用窗口及其全部子窗口的输入法。

    锁定界面禁用 IME:中文输入法开启时字母键会变成组字事件(e.key='Process'),
    页面将收不到任何字符,导致无法输入密码。设置界面保持 IME 可用。
    """
    try:
        native = getattr(window, "native", None)
        if native is None:
            return False
        hwnd = native.Handle.ToInt64()
        if enable:
            return bool(_imm32.ImmAssociateContextEx(hwnd, None, IACE_DEFAULT))

        ok = bool(_imm32.ImmAssociateContextEx(hwnd, None, IACE_CHILDREN))
        # 逐个子窗口(WebView2 控件)再禁用一遍,确保覆盖
        def _disable(child, _lparam):
            _imm32.ImmAssociateContext(child, None)
            return True

        proc = WNDENUMPROC(_disable)
        _user32.EnumChildWindows(hwnd, proc, 0)
        return ok
    except Exception:
        return False


# ----------------------------------------------------------------------------
# 密码存取(PBKDF2-HMAC-SHA256 + 随机盐)
# ----------------------------------------------------------------------------
def load_config():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if cfg.get("salt_b64") and cfg.get("hash_b64"):
            return cfg
    except (OSError, ValueError):
        pass
    return None


def check_password(cfg, password: str) -> bool:
    try:
        salt = base64.b64decode(cfg["salt_b64"])
        expected = base64.b64decode(cfg["hash_b64"])
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(cfg.get("iters", PBKDF2_ITERS))
        )
        return hmac.compare_digest(actual, expected)
    except (KeyError, ValueError):
        return False


# ----------------------------------------------------------------------------
# 锁定控制器:键盘钩子 + 鼠标范围锁定
# ----------------------------------------------------------------------------
class LockController:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled            # False = 预览模式,不锁定键鼠
        self.locked_at = 0.0
        self._active = threading.Event()
        self._proc = None
        self._hook_thread = None
        self._clip_thread = None
        self._attempts = 0
        self._last_fail = 0.0

    # ---- 键盘钩子 ----
    def _hook_proc(self, n_code, w_param, l_param):
        if n_code >= 0 and self._active.is_set():
            kb = ctypes.cast(l_param, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
            vk = kb.vkCode
            alt = bool(kb.flags & LLKHF_ALTDOWN) or (
                _user32.GetAsyncKeyState(VK_MENU) & 0x8000
            )
            ctrl = bool(_user32.GetAsyncKeyState(VK_CONTROL) & 0x8000)
            if ctrl and alt and vk == VK_F12:
                # 紧急退出:Ctrl+Alt+F12(全局生效,不依赖窗口焦点)
                self._active.clear()
                _user32.ClipCursor(None)
                os._exit(0)
            if vk in (VK_LWIN, VK_RWIN):
                return 1  # 屏蔽 Win 键(含 Win+L / Win+D 等)
            if alt and vk in (VK_TAB, VK_ESCAPE, VK_F4):
                return 1  # 屏蔽 Alt+Tab / Alt+Esc / Alt+F4
            if ctrl and vk == VK_ESCAPE:
                return 1  # 屏蔽 Ctrl+Esc
        return _user32.CallNextHookEx(None, n_code, w_param, l_param)

    def _hook_worker(self):
        handle = _user32.SetWindowsHookExW(WH_KEYBOARD_LL, self._proc, None, 0)
        msg = wintypes.MSG()
        while _user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            _user32.TranslateMessage(ctypes.byref(msg))
            _user32.DispatchMessageW(ctypes.byref(msg))
        if handle:
            _user32.UnhookWindowsHookEx(handle)

    # ---- 鼠标锁定 ----
    def _clip_worker(self):
        rect = RECT()
        rect.left = _user32.GetSystemMetrics(76)    # SM_XVIRTUALSCREEN
        rect.top = _user32.GetSystemMetrics(77)     # SM_YVIRTUALSCREEN
        rect.right = rect.left + _user32.GetSystemMetrics(78)
        rect.bottom = rect.top + _user32.GetSystemMetrics(79)
        while self._active.is_set():
            _user32.ClipCursor(ctypes.byref(rect))
            time.sleep(0.8)
        _user32.ClipCursor(None)

    # ---- 开关 ----
    def start_protection(self):
        if not self.enabled or self._active.is_set():
            return
        self._active.set()
        self.locked_at = time.time()
        self._attempts = 0
        self._proc = HOOKPROC(self._hook_proc)
        self._hook_thread = threading.Thread(target=self._hook_worker, daemon=True)
        self._clip_thread = threading.Thread(target=self._clip_worker, daemon=True)
        self._hook_thread.start()
        self._clip_thread.start()

    def stop_protection(self):
        if not self._active.is_set():
            return
        self._active.clear()
        tid = self._hook_thread.ident if self._hook_thread else None
        if tid:
            _user32.PostThreadMessageW(tid, WM_QUIT, 0, 0)
        if self._hook_thread:
            self._hook_thread.join(timeout=3)
        if self._clip_thread:
            self._clip_thread.join(timeout=3)
        _user32.ClipCursor(None)

    # ---- 校验 ----
    def verify(self, password: str) -> dict:
        cfg = load_config()
        if not cfg:
            return {"ok": False, "error": "no_password"}
        now = time.time()
        if self._attempts >= MAX_ATTEMPTS:
            remain = COOLDOWN_SECONDS - (now - self._last_fail)
            if remain > 0:
                return {
                    "ok": False,
                    "attempts": self._attempts,
                    "cooldown": int(remain) + 1,
                }
        if check_password(cfg, password):
            self._attempts = 0
            return {"ok": True}
        self._attempts += 1
        self._last_fail = now
        result = {"ok": False, "attempts": self._attempts}
        if self._attempts >= MAX_ATTEMPTS:
            result["cooldown"] = COOLDOWN_SECONDS
        return result


# ----------------------------------------------------------------------------
# 暴露给前端 JS 的接口
# ----------------------------------------------------------------------------
class JsApi:
    def __init__(self, lock: LockController, window_holder: dict):
        self.lock = lock
        self.window_holder = window_holder

    def get_state(self) -> dict:
        cfg = load_config()
        return {
            "first_run": cfg is None,
            "locked_at": self.lock.locked_at,
            "hint": (cfg or {}).get("hint", ""),
            "version": "1.0",
        }

    def get_battery(self) -> dict:
        return get_battery()

    def verify_password(self, password: str) -> dict:
        return self.lock.verify(password or "")

    def set_password(self, password: str, hint: str) -> dict:
        if not isinstance(password, str) or len(password) < 4:
            return {"ok": False, "error": "too_short"}
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERS
        )
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "v": 1,
                    "salt_b64": base64.b64encode(salt).decode(),
                    "hash_b64": base64.b64encode(digest).decode(),
                    "iters": PBKDF2_ITERS,
                    "hint": hint or "",
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
        self.lock.start_protection()  # 幂等:已在锁定状态则无操作
        return {"ok": True}

    def unlock_and_exit(self):
        self.lock.stop_protection()
        threading.Thread(target=self._shutdown, daemon=True).start()

    def set_ime(self, enabled) -> dict:
        w = self.window_holder.get("window")
        if w is not None:
            return {"ok": set_window_ime(w, bool(enabled))}
        return {"ok": False}

    def _shutdown(self):
        # WebView2 销毁较慢:先隐藏窗口让屏幕立即恢复,再后台销毁进程
        watchdog = threading.Timer(10.0, os._exit, args=(0,))
        watchdog.daemon = True
        watchdog.start()
        try:
            for w in list(webview.windows):
                try:
                    w.hide()
                except Exception:
                    pass
            for w in list(webview.windows):
                w.destroy()
        except Exception:
            pass
        os._exit(0)


# ----------------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="挂机锁 IdleLock")
    parser.add_argument("--idle", type=int, metavar="MIN", default=0,
                        help="系统空闲 N 分钟后自动锁定(进程常驻)")
    parser.add_argument("--preview", action="store_true", help="预览模式(不锁定键鼠)")
    parser.add_argument("--selftest", action="store_true", help="环境自检后退出")
    args = parser.parse_args()

    global webview
    try:
        import webview
    except ImportError:
        print("缺少依赖:请先执行  pip install pywebview")
        sys.exit(1)

    if args.selftest:
        window = webview.create_window("selftest", html="<h1>ok</h1>", hidden=True)

        def _close():
            time.sleep(1.5)
            print("SELFTEST_OK")
            window.destroy()

        webview.start(_close)
        return

    lock = LockController(enabled=not args.preview)
    window_holder = {"window": None}
    api = JsApi(lock, window_holder)

    if args.preview:
        window = webview.create_window(
            "挂机锁 · IdleLock(预览模式)",
            str(UI_FILE),
            js_api=api,
            width=1180,
            height=760,
            resizable=True,
            background_color="#070912",
        )
        window_holder["window"] = window
        webview.start()
        return

    if args.idle > 0:
        window = webview.create_window(
            "挂机锁 · IdleLock",
            str(UI_FILE),
            js_api=api,
            hidden=True,
            fullscreen=True,
            frameless=True,
            easy_drag=False,
            on_top=True,
            background_color="#070912",
        )
        window_holder["window"] = window
        threading.Timer(2.5, lambda: set_window_ime(window, bool(load_config()))).start()

        def idle_watch():
            threshold = args.idle * 60
            while True:
                time.sleep(5)
                if system_idle_seconds() >= threshold:
                    lock.start_protection()
                    try:
                        window.show()
                    except Exception:
                        pass
                    break

        try:
            webview.start(idle_watch)
        finally:
            lock.stop_protection()
        return

    # 默认:已设置密码则立即锁定;首次使用先展示设置界面
    # (设置阶段不锁定键鼠、不装键盘钩子,Alt+F4 可随时退出,防止用户被自己锁死)
    if load_config():
        lock.start_protection()
    window = webview.create_window(
        "挂机锁 · IdleLock",
        str(UI_FILE),
        js_api=api,
        fullscreen=True,
        frameless=True,
        easy_drag=False,
        on_top=True,
        focus=True,
        background_color="#070912",
    )
    window_holder["window"] = window
    threading.Timer(2.5, lambda: set_window_ime(window, bool(load_config()))).start()
    try:
        webview.start()
    finally:
        lock.stop_protection()


if __name__ == "__main__":
    main()
