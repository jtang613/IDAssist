#!/usr/bin/env python3

"""
IDA Compatibility Layer - Provides logging, main-thread execution, and utility functions
for the IDAssist plugin running inside IDA Pro.
"""

import os
import hashlib

try:
    import idaapi
    import ida_kernwin
    import ida_nalt

    _IN_IDA = True
except ImportError:
    _IN_IDA = False


class IDALogger:
    """Logger that wraps ida_kernwin.msg() for IDA output window logging.

    Provides the same interface as binaryninja.log.Logger so copied code
    works with a simple ``from src.ida_compat import log`` replacement.
    """

    PREFIX = "[IDAssist]"

    @staticmethod
    def log_debug(msg):
        if _IN_IDA:
            ida_kernwin.msg(f"{IDALogger.PREFIX} DEBUG: {msg}\n")
        else:
            print(f"{IDALogger.PREFIX} DEBUG: {msg}")

    @staticmethod
    def log_info(msg):
        if _IN_IDA:
            ida_kernwin.msg(f"{IDALogger.PREFIX} INFO: {msg}\n")
        else:
            print(f"{IDALogger.PREFIX} INFO: {msg}")

    @staticmethod
    def log_warn(msg):
        if _IN_IDA:
            ida_kernwin.msg(f"{IDALogger.PREFIX} WARN: {msg}\n")
        else:
            print(f"{IDALogger.PREFIX} WARN: {msg}")

    @staticmethod
    def log_error(msg):
        if _IN_IDA:
            ida_kernwin.msg(f"{IDALogger.PREFIX} ERROR: {msg}\n")
        else:
            print(f"{IDALogger.PREFIX} ERROR: {msg}")


# Global logger instance - replaces binaryninja.log usage across the codebase
log = IDALogger()


def execute_on_main_thread(callback):
    """Execute a callback on IDA's main thread.

    IDA requires all IDB modifications to happen on the main thread.
    This wraps ``idaapi.execute_sync()`` with ``MFF_FAST``.

    Args:
        callback: A callable (no arguments) to execute on the main thread.

    Returns:
        The return value of ``idaapi.execute_sync()``.
    """
    if not _IN_IDA:
        # Outside IDA, just call directly
        return callback()

    return idaapi.execute_sync(callback, idaapi.MFF_FAST)


def get_user_data_dir():
    """Get the IDAssist user data directory.

    Returns:
        Path to ``~/.idapro/idassist/`` (created if it doesn't exist).
    """
    if _IN_IDA:
        user_dir = idaapi.get_user_idadir()
    else:
        user_dir = os.path.expanduser("~/.idapro")

    data_dir = os.path.join(user_dir, "idassist")
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


def get_binary_hash():
    """Get SHA-256 hash of the currently loaded binary.

    Returns:
        Hex-encoded SHA-256 hash string, or empty string on failure.
    """
    try:
        if not _IN_IDA:
            return ""

        input_path = ida_nalt.get_input_file_path()
        if not input_path or not os.path.exists(input_path):
            return ""

        sha256 = hashlib.sha256()
        with open(input_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    except Exception as e:
        log.log_error(f"Failed to compute binary hash: {e}")
        return ""


def is_in_ida():
    """Check if we are running inside IDA Pro."""
    return _IN_IDA


def check_qt_platform_plugins():
    """Lightweight file-existence check for Qt platform plugins.

    This does NOT import PySide6 — it checks the filesystem to detect
    whether the platform plugins directory exists. Call this before
    importing PySide6 in OnCreate to prevent the fatal abort() that Qt
    triggers when platform plugins are missing (which Python cannot catch).

    Returns:
        (ok: bool, error_msg: str or None)
    """
    try:
        import importlib.util
        spec = importlib.util.find_spec("PySide6")
        if spec is None or spec.origin is None:
            return False, "PySide6 is not installed or not importable"

        pyside6_dir = os.path.dirname(spec.origin)
        plugins_dir = os.path.join(pyside6_dir, "Qt", "plugins", "platforms")
        if not os.path.isdir(plugins_dir):
            return False, (
                f"Qt platform plugins directory not found at {plugins_dir}. "
                "This usually means PySide6 is incomplete or corrupted. "
                "Try: pip install --force-reinstall PySide6"
            )
        return True, None
    except Exception as e:
        return False, f"Qt platform plugin check failed: {e}"


def check_qt_environment():
    """Validate the Qt/PySide6 environment for use in IDA plugins.

    Performs import tests, version logging, conflict detection, and
    platform plugin checks.

    Returns:
        (ok: bool, diagnostics: str)
    """
    diag_lines = []

    # 1. Import test
    try:
        import PySide6
        import PySide6.QtCore
    except ImportError as e:
        return False, f"PySide6 import failed: {e}"

    # 2. Version logging
    pyside_ver = PySide6.__version__
    qt_ver = PySide6.QtCore.qVersion()
    diag_lines.append(f"PySide6 {pyside_ver}, Qt {qt_ver}")

    # 3. Conflicting install detection
    pyside_path = os.path.realpath(PySide6.__file__)
    if "site-packages" in pyside_path:
        # Check if this looks like a pip-installed copy rather than IDA's bundled one
        ida_dir = ""
        if _IN_IDA:
            try:
                ida_dir = os.path.dirname(idaapi.get_ida_directory() or "")
            except Exception:
                pass
        if ida_dir and not pyside_path.startswith(ida_dir):
            diag_lines.append(
                f"WARNING: PySide6 loaded from pip site-packages ({pyside_path}) "
                "which may shadow IDA's bundled Qt and cause crashes. "
                "Consider: pip uninstall PySide6"
            )

    # 4. Platform plugin check
    ok, err = check_qt_platform_plugins()
    if not ok:
        diag_lines.append(f"FATAL: {err}")
        return False, "; ".join(diag_lines)

    # 5. QApplication check
    try:
        from PySide6.QtWidgets import QApplication
        if QApplication.instance() is None:
            diag_lines.append("Note: QApplication not yet created (may be normal during early init)")
    except Exception:
        pass

    return True, "; ".join(diag_lines)
