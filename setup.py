"""
Setup script for building the frozen_memory C extension.

Usage:
    python setup.py build_ext --inplace

The C extension is optional. If it cannot be compiled, the package
falls back to the ctypes-based implementation automatically.
"""

from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
import sys


class OptionalBuildExt(build_ext):
    """
    Build C extensions as optional.

    If compilation fails (e.g., no MSVC, no GCC), the build
    continues without the extension. The Python fallback
    (frozen_memory_fallback.py) handles this at runtime.
    """

    def build_extension(self, ext):
        try:
            super().build_extension(ext)
        except Exception as e:
            print(f"\n{'='*60}")
            print(f"WARNING: Could not compile C extension '{ext.name}'")
            print(f"Reason: {e}")
            print(f"The package will use the Python ctypes fallback instead.")
            print(f"OS-level memory protection is still active via ctypes.")
            print(f"{'='*60}\n")


frozen_memory_ext = Extension(
    "sovereign_shield.frozen_memory",
    sources=["sovereign_shield/frozen_memory.c"],
    language="c",
)

# Only add platform-specific libraries
if sys.platform == "win32":
    frozen_memory_ext.libraries = ["kernel32"]

setup(
    ext_modules=[frozen_memory_ext],
    cmdclass={"build_ext": OptionalBuildExt},
)
