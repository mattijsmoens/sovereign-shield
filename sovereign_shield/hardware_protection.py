"""
Hardware Memory Protection — Auto-loading wrapper.
====================================================
Tries to load the C extension first. Falls back to ctypes implementation.

Usage:
    from sovereign_shield.hardware_protection import freeze, verify, is_protected, destroy
"""

import logging

logger = logging.getLogger(__name__)

_backend = None

try:
    from sovereign_shield import frozen_memory as _backend
    BACKEND = "c_extension"
    logger.info("[HardwareProtection] C extension loaded — OS-level memory protection active.")
except ImportError:
    try:
        from sovereign_shield import frozen_memory_fallback as _backend
        BACKEND = "ctypes_fallback"
        logger.info(
            "[HardwareProtection] C extension unavailable. "
            "Using ctypes fallback — OS-level memory protection active."
        )
    except (ImportError, OSError) as e:
        BACKEND = "none"
        logger.warning(
            f"[HardwareProtection] No hardware memory protection available: {e}. "
            f"FrozenNamespace will use Python-level protection only."
        )


def is_available():
    """Check if hardware memory protection is available."""
    return _backend is not None


def freeze(data):
    """Freeze bytes into hardware-protected read-only memory."""
    if _backend is None:
        raise RuntimeError(
            "Hardware memory protection is not available. "
            "Install the C extension or ensure ctypes is available."
        )
    return _backend.freeze(data)


def verify(buffer, expected_hash):
    """Verify frozen buffer against SHA-256 hash."""
    if _backend is None:
        raise RuntimeError("Hardware memory protection is not available.")
    return _backend.verify(buffer, expected_hash)


def is_protected(buffer):
    """Check if the memory page is still read-only."""
    if _backend is None:
        raise RuntimeError("Hardware memory protection is not available.")
    return _backend.is_protected(buffer)


def destroy(buffer):
    """Securely wipe and free the memory page."""
    if _backend is None:
        raise RuntimeError("Hardware memory protection is not available.")
    return _backend.destroy(buffer)


def page_size():
    """Return the OS memory page size."""
    if _backend is None:
        return 4096  # Default
    return _backend.page_size()
