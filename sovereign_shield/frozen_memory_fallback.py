"""
frozen_memory_fallback — Pure-Python ctypes Fallback for frozen_memory.
========================================================================
When the C extension cannot be compiled, this module provides the same
API using ctypes to call OS memory protection functions directly.

This is slightly less secure than the C extension (since ctypes must
remain available), but provides the same OS-level protection.

API matches frozen_memory.c exactly:
    freeze(data: bytes) -> FrozenBuffer
    verify(buffer: FrozenBuffer, expected_hash: bytes) -> bool
    is_protected(buffer: FrozenBuffer) -> bool
    destroy(buffer: FrozenBuffer) -> None
    page_size() -> int
"""

import ctypes
import ctypes.util
import hashlib
import hmac
import sys
import os
import logging

logger = logging.getLogger(__name__)

_is_windows = sys.platform == "win32"


# ================================================================
# Platform-specific setup
# ================================================================

if _is_windows:
    _kernel32 = ctypes.windll.kernel32

    _VirtualAlloc = _kernel32.VirtualAlloc
    _VirtualAlloc.restype = ctypes.c_void_p
    _VirtualAlloc.argtypes = [
        ctypes.c_void_p,  # lpAddress
        ctypes.c_size_t,  # dwSize
        ctypes.c_ulong,   # flAllocationType
        ctypes.c_ulong,   # flProtect
    ]

    _VirtualProtect = _kernel32.VirtualProtect
    _VirtualProtect.restype = ctypes.c_int
    _VirtualProtect.argtypes = [
        ctypes.c_void_p,                    # lpAddress
        ctypes.c_size_t,                    # dwSize
        ctypes.c_ulong,                     # flNewProtect
        ctypes.POINTER(ctypes.c_ulong),     # lpflOldProtect
    ]

    _VirtualFree = _kernel32.VirtualFree
    _VirtualFree.restype = ctypes.c_int
    _VirtualFree.argtypes = [
        ctypes.c_void_p,  # lpAddress
        ctypes.c_size_t,  # dwSize
        ctypes.c_ulong,   # dwFreeType
    ]

    _VirtualQuery = _kernel32.VirtualQuery
    _VirtualQuery.restype = ctypes.c_size_t
    _VirtualQuery.argtypes = [
        ctypes.c_void_p,  # lpAddress
        ctypes.c_void_p,  # lpBuffer
        ctypes.c_size_t,  # dwLength
    ]

    _GetSystemInfo = _kernel32.GetSystemInfo

    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_RELEASE = 0x8000
    PAGE_READWRITE = 0x04
    PAGE_READONLY = 0x02

    class SYSTEM_INFO(ctypes.Structure):
        _fields_ = [
            ("wProcessorArchitecture", ctypes.c_ushort),
            ("wReserved", ctypes.c_ushort),
            ("dwPageSize", ctypes.c_ulong),
            ("lpMinimumApplicationAddress", ctypes.c_void_p),
            ("lpMaximumApplicationAddress", ctypes.c_void_p),
            ("dwActiveProcessorMask", ctypes.c_void_p),
            ("dwNumberOfProcessors", ctypes.c_ulong),
            ("dwProcessorType", ctypes.c_ulong),
            ("dwAllocationGranularity", ctypes.c_ulong),
            ("wProcessorLevel", ctypes.c_ushort),
            ("wProcessorRevision", ctypes.c_ushort),
        ]

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.c_ulong),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_ulong),
            ("Protect", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
        ]

else:
    # Unix (Linux, macOS)
    _libc_name = ctypes.util.find_library("c")
    if _libc_name is None:
        raise ImportError(
            "Could not locate libc. Hardware memory protection is unavailable."
        )
    _libc = ctypes.CDLL(_libc_name, use_errno=True)

    _mmap = _libc.mmap
    _mmap.restype = ctypes.c_void_p
    _mmap.argtypes = [
        ctypes.c_void_p,  # addr
        ctypes.c_size_t,  # length
        ctypes.c_int,     # prot
        ctypes.c_int,     # flags
        ctypes.c_int,     # fd
        ctypes.c_longlong,    # offset (off_t) — must be c_longlong on 64-bit
    ]

    _mprotect = _libc.mprotect
    _mprotect.restype = ctypes.c_int
    _mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]

    _munmap = _libc.munmap
    _munmap.restype = ctypes.c_int
    _munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

    PROT_READ = 0x1
    PROT_WRITE = 0x2
    MAP_PRIVATE = 0x02
    MAP_ANONYMOUS = 0x20 if sys.platform == "linux" else 0x1000  # macOS uses 0x1000
    MAP_FAILED = ctypes.c_void_p(-1).value


# ================================================================
# Page size
# ================================================================

def page_size():
    """Return the OS memory page size in bytes."""
    if _is_windows:
        si = SYSTEM_INFO()
        _GetSystemInfo(ctypes.byref(si))
        return si.dwPageSize
    else:
        return os.sysconf("SC_PAGE_SIZE")


# ================================================================
# FrozenBuffer
# ================================================================

class FrozenBuffer:
    """Read-only memory buffer backed by OS page protection."""

    __slots__ = ("_ptr", "_data_size", "_alloc_size", "_is_protected")

    def __init__(self, ptr, data_size, alloc_size):
        self._ptr = ptr
        self._data_size = data_size
        self._alloc_size = alloc_size
        self._is_protected = True

    @property
    def data(self):
        """Read-only access to frozen data."""
        if self._ptr is None:
            raise RuntimeError("Buffer has been destroyed.")
        return ctypes.string_at(self._ptr, self._data_size)

    @property
    def size(self):
        return self._data_size

    @property
    def protected(self):
        return self._is_protected

    def __del__(self):
        # Guard against interpreter shutdown (ctypes may be gone)
        try:
            if self._ptr is not None:
                destroy(self)
        except Exception:
            pass  # Interpreter shutting down, ctypes unavailable


# ================================================================
# Public API
# ================================================================

def freeze(data):
    """
    freeze(data: bytes) -> FrozenBuffer
    Copy data into a dedicated memory page and mark it read-only.
    """
    if not isinstance(data, bytes) or len(data) == 0:
        raise ValueError("Data must be non-empty bytes.")

    ps = page_size()
    alloc_size = ((len(data) + ps - 1) // ps) * ps

    # Allocate
    if _is_windows:
        ptr = _VirtualAlloc(None, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not ptr:
            raise MemoryError("VirtualAlloc failed.")
    else:
        ptr = _mmap(None, alloc_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        if ptr == MAP_FAILED or ptr is None:
            raise MemoryError("mmap failed.")

    # Copy data
    ctypes.memmove(ptr, data, len(data))

    # Zero remaining space
    if len(data) < alloc_size:
        ctypes.memset(ptr + len(data), 0, alloc_size - len(data))

    # Mark read-only — THE CRITICAL STEP
    if _is_windows:
        old_protect = ctypes.c_ulong()
        result = _VirtualProtect(ptr, alloc_size, PAGE_READONLY, ctypes.byref(old_protect))
        if not result:
            _VirtualFree(ptr, 0, MEM_RELEASE)
            raise OSError("VirtualProtect failed.")
    else:
        result = _mprotect(ptr, alloc_size, PROT_READ)
        if result != 0:
            _munmap(ptr, alloc_size)
            raise OSError("mprotect failed.")

    # M-17: Don't log raw memory addresses (ASLR information leak)
    logger.info(f"[frozen_memory] Froze {len(data)} bytes ({alloc_size} allocated, page-aligned)")
    return FrozenBuffer(ptr, len(data), alloc_size)


def verify(buffer, expected_hash):
    """
    verify(buffer: FrozenBuffer, expected_hash: bytes) -> bool
    Verify buffer contents against SHA-256 hash.
    """
    if buffer._ptr is None:
        raise RuntimeError("Buffer has been destroyed.")
    computed = hashlib.sha256(buffer.data).digest()
    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(computed, expected_hash)


def is_protected(buffer):
    """
    is_protected(buffer: FrozenBuffer) -> bool
    Check if the memory page is still marked read-only.
    """
    if buffer._ptr is None:
        raise RuntimeError("Buffer has been destroyed.")

    if _is_windows:
        mbi = MEMORY_BASIC_INFORMATION()
        result = _VirtualQuery(buffer._ptr, ctypes.byref(mbi), ctypes.sizeof(mbi))
        if result == 0:
            return buffer._is_protected
        return mbi.Protect == PAGE_READONLY
    else:
        # M-16: Query /proc/self/maps on Linux for actual page permissions
        try:
            import sys
            if sys.platform == "linux":
                addr = buffer._ptr
                with open("/proc/self/maps", "r") as f:
                    for line in f:
                        parts = line.split()
                        if not parts:
                            continue
                        addr_range = parts[0].split("-")
                        if len(addr_range) != 2:
                            continue
                        start = int(addr_range[0], 16)
                        end = int(addr_range[1], 16)
                        if start <= addr < end:
                            perms = parts[1] if len(parts) > 1 else ""
                            # 'r--p' means read-only, 'rw-p' means writable
                            return "w" not in perms
        except (OSError, ValueError, IndexError):
            pass
        # Fallback to cached flag if /proc unavailable (macOS, etc.)
        return buffer._is_protected


def destroy(buffer):
    """
    destroy(buffer: FrozenBuffer) -> None
    Securely wipe and free the memory page.
    """
    if buffer._ptr is None:
        return

    # Re-enable write for secure wipe
    if buffer._is_protected:
        if _is_windows:
            old_protect = ctypes.c_ulong()
            _VirtualProtect(buffer._ptr, buffer._alloc_size,
                           PAGE_READWRITE, ctypes.byref(old_protect))
        else:
            _mprotect(buffer._ptr, buffer._alloc_size, PROT_READ | PROT_WRITE)
        buffer._is_protected = False

    # Secure wipe
    ctypes.memset(buffer._ptr, 0, buffer._alloc_size)

    # Free
    if _is_windows:
        _VirtualFree(buffer._ptr, 0, MEM_RELEASE)
    else:
        _munmap(buffer._ptr, buffer._alloc_size)

    buffer._ptr = None
    buffer._data_size = 0
    buffer._alloc_size = 0
