/*
 * frozen_memory — OS-Level Hardware Memory Protection for FrozenNamespace
 * ========================================================================
 * C extension that allocates dedicated memory pages and marks them read-only
 * at the OS level. Any write attempt (from Python, ctypes, C extensions, or
 * assembly) triggers a hardware fault (SIGSEGV/ACCESS_VIOLATION).
 *
 * API:
 *   frozen_memory.freeze(data: bytes) -> FrozenBuffer
 *   frozen_memory.verify(buffer: FrozenBuffer, expected_hash: bytes) -> bool
 *   frozen_memory.is_protected(buffer: FrozenBuffer) -> bool
 *   frozen_memory.destroy(buffer: FrozenBuffer) -> None
 *
 * Platforms: Linux, macOS, Windows
 * Dependencies: None (OS system calls only)
 *
 * Copyright (c) 2026 Mattijs Moens / Sovereign Shield. All rights reserved.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/mman.h>
    #include <unistd.h>
#endif

/* SHA-256 implementation (minimal, no dependencies) */
/* We use Python's hashlib for hashing instead — simpler and auditable */

/* Constant-time comparison to prevent timing side-channel attacks.
 * Unlike memcmp, this always compares ALL bytes regardless of mismatch. */
static int constant_time_compare(const void *a, const void *b, size_t len) {
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= x[i] ^ y[i];
    }
    return result == 0;  /* 1 if equal, 0 if different */
}

/* Secure memory wipe that cannot be optimized away.
 * Uses volatile pointer to force the compiler to execute the write. */
static void secure_wipe(void *ptr, size_t size) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    for (size_t i = 0; i < size; i++) {
        p[i] = 0;
    }
}


/* ================================================================
 * Page size helper
 * ================================================================ */

static size_t get_page_size(void) {
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (size_t)si.dwPageSize;
#else
    return (size_t)sysconf(_SC_PAGESIZE);
#endif
}


/* ================================================================
 * FrozenBuffer type
 * ================================================================ */

typedef struct {
    PyObject_HEAD
    void *data;           /* Pointer to protected memory page */
    size_t data_size;     /* Size of the actual data */
    size_t alloc_size;    /* Size of the allocated region (page-aligned) */
    int is_protected;     /* 1 if memory is read-only, 0 if not */
} FrozenBufferObject;

static void FrozenBuffer_dealloc(FrozenBufferObject *self);
static PyObject *FrozenBuffer_get_data(FrozenBufferObject *self, void *closure);
static PyObject *FrozenBuffer_get_size(FrozenBufferObject *self, void *closure);
static PyObject *FrozenBuffer_get_protected(FrozenBufferObject *self, void *closure);

static PyGetSetDef FrozenBuffer_getsetters[] = {
    {"data", (getter)FrozenBuffer_get_data, NULL, "Read-only access to frozen data", NULL},
    {"size", (getter)FrozenBuffer_get_size, NULL, "Size of frozen data in bytes", NULL},
    {"protected", (getter)FrozenBuffer_get_protected, NULL, "Whether memory is read-only", NULL},
    {NULL}
};

static PyTypeObject FrozenBufferType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "frozen_memory.FrozenBuffer",
    .tp_doc = "Read-only memory buffer backed by OS page protection.",
    .tp_basicsize = sizeof(FrozenBufferObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = NULL,  /* Prevent FrozenBuffer() from Python — only freeze() can create */
    .tp_dealloc = (destructor)FrozenBuffer_dealloc,
    .tp_getset = FrozenBuffer_getsetters,
};


/* ================================================================
 * Platform-specific memory operations
 * ================================================================ */

static void *alloc_page(size_t size) {
#ifdef _WIN32
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (ptr == MAP_FAILED) ? NULL : ptr;
#endif
}

static int protect_page(void *ptr, size_t size) {
#ifdef _WIN32
    DWORD old_protect;
    return VirtualProtect(ptr, size, PAGE_READONLY, &old_protect) ? 0 : -1;
#else
    return mprotect(ptr, size, PROT_READ);
#endif
}

static int unprotect_page(void *ptr, size_t size) {
#ifdef _WIN32
    DWORD old_protect;
    return VirtualProtect(ptr, size, PAGE_READWRITE, &old_protect) ? 0 : -1;
#else
    return mprotect(ptr, size, PROT_READ | PROT_WRITE);
#endif
}

static void free_page(void *ptr, size_t size) {
#ifdef _WIN32
    VirtualFree(ptr, 0, MEM_RELEASE);
#else
    munmap(ptr, size);
#endif
}

static int check_protection(void *ptr, size_t size) {
#ifdef _WIN32
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0)
        return 0;
    return (mbi.Protect == PAGE_READONLY) ? 1 : 0;
#else
    /* On Unix, we rely on our internal flag since reading /proc/self/maps
       is Linux-specific. The mprotect call is the source of truth. */
    (void)ptr;
    (void)size;
    return -1;  /* Use internal flag instead */
#endif
}


/* ================================================================
 * FrozenBuffer methods
 * ================================================================ */

static void FrozenBuffer_dealloc(FrozenBufferObject *self) {
    if (self->data) {
        /* Secure wipe: temporarily re-enable write, zero, then free */
        if (self->is_protected) {
            unprotect_page(self->data, self->alloc_size);
        }
        secure_wipe(self->data, self->alloc_size);
        free_page(self->data, self->alloc_size);
        self->data = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *FrozenBuffer_get_data(FrozenBufferObject *self, void *closure) {
    if (!self->data) {
        PyErr_SetString(PyExc_RuntimeError, "Buffer has been destroyed.");
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char *)self->data, self->data_size);
}

static PyObject *FrozenBuffer_get_size(FrozenBufferObject *self, void *closure) {
    return PyLong_FromSize_t(self->data_size);
}

static PyObject *FrozenBuffer_get_protected(FrozenBufferObject *self, void *closure) {
    if (self->is_protected) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}


/* ================================================================
 * Module-level functions
 * ================================================================ */

static PyObject *frozen_memory_freeze(PyObject *self, PyObject *args) {
    const char *data;
    Py_ssize_t data_len;

    if (!PyArg_ParseTuple(args, "y#", &data, &data_len))
        return NULL;

    if (data_len <= 0) {
        PyErr_SetString(PyExc_ValueError, "Data must be non-empty.");
        return NULL;
    }

    /* Calculate page-aligned allocation size */
    size_t page_size = get_page_size();
    size_t alloc_size = ((size_t)data_len + page_size - 1) & ~(page_size - 1);
    if (alloc_size < page_size)
        alloc_size = page_size;

    /* Allocate dedicated memory page(s) */
    void *page = alloc_page(alloc_size);
    if (!page) {
        PyErr_SetString(PyExc_MemoryError, "Failed to allocate memory page.");
        return NULL;
    }

    /* Copy data into the page */
    memcpy(page, data, (size_t)data_len);
    /* Zero remaining space in the page */
    if ((size_t)data_len < alloc_size) {
        memset((char *)page + data_len, 0, alloc_size - (size_t)data_len);
    }

    /* Mark as read-only — THE CRITICAL STEP */
    if (protect_page(page, alloc_size) != 0) {
        free_page(page, alloc_size);
        PyErr_SetString(PyExc_OSError, "Failed to set memory page as read-only.");
        return NULL;
    }

    /* Create FrozenBuffer object */
    FrozenBufferObject *buf = PyObject_New(FrozenBufferObject, &FrozenBufferType);
    if (!buf) {
        /* Need to unprotect before freeing */
        unprotect_page(page, alloc_size);
        free_page(page, alloc_size);
        return NULL;
    }

    buf->data = page;
    buf->data_size = (size_t)data_len;
    buf->alloc_size = alloc_size;
    buf->is_protected = 1;

    return (PyObject *)buf;
}

static PyObject *frozen_memory_verify(PyObject *self, PyObject *args) {
    FrozenBufferObject *buf;
    const char *expected_hash;
    Py_ssize_t hash_len;

    if (!PyArg_ParseTuple(args, "O!y#", &FrozenBufferType, &buf,
                          &expected_hash, &hash_len))
        return NULL;

    if (!buf->data) {
        PyErr_SetString(PyExc_RuntimeError, "Buffer has been destroyed.");
        return NULL;
    }

    /* Use Python's hashlib for SHA-256 */
    PyObject *hashlib = PyImport_ImportModule("hashlib");
    if (!hashlib) return NULL;

    PyObject *data_bytes = PyBytes_FromStringAndSize(
        (const char *)buf->data, buf->data_size
    );
    if (!data_bytes) { Py_DECREF(hashlib); return NULL; }

    PyObject *sha256 = PyObject_CallMethod(hashlib, "sha256", "O", data_bytes);
    Py_DECREF(data_bytes);
    Py_DECREF(hashlib);
    if (!sha256) return NULL;

    PyObject *digest = PyObject_CallMethod(sha256, "digest", NULL);
    Py_DECREF(sha256);
    if (!digest) return NULL;

    /* Compare digests */
    char *computed;
    Py_ssize_t computed_len;
    if (PyBytes_AsStringAndSize(digest, &computed, &computed_len) < 0) {
        Py_DECREF(digest);
        return NULL;
    }

    int match = (computed_len == hash_len &&
                 constant_time_compare(computed, expected_hash, (size_t)hash_len));
    Py_DECREF(digest);

    if (match) Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

static PyObject *frozen_memory_is_protected(PyObject *self, PyObject *args) {
    FrozenBufferObject *buf;

    if (!PyArg_ParseTuple(args, "O!", &FrozenBufferType, &buf))
        return NULL;

    if (!buf->data) {
        PyErr_SetString(PyExc_RuntimeError, "Buffer has been destroyed.");
        return NULL;
    }

    /* Check OS-level protection on Windows; use internal flag elsewhere */
    int result = check_protection(buf->data, buf->alloc_size);
    if (result == -1) {
        /* Fallback to internal flag */
        result = buf->is_protected;
    }

    if (result) Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

static PyObject *frozen_memory_destroy(PyObject *self, PyObject *args) {
    FrozenBufferObject *buf;

    if (!PyArg_ParseTuple(args, "O!", &FrozenBufferType, &buf))
        return NULL;

    if (!buf->data) {
        Py_RETURN_NONE;  /* Already destroyed */
    }

    /* Secure destruction:
     * 1. Re-enable write
     * 2. Zero all data
     * 3. Free the page
     */
    if (buf->is_protected) {
        unprotect_page(buf->data, buf->alloc_size);
        buf->is_protected = 0;
    }
    secure_wipe(buf->data, buf->alloc_size);
    free_page(buf->data, buf->alloc_size);
    buf->data = NULL;
    buf->data_size = 0;
    buf->alloc_size = 0;

    Py_RETURN_NONE;
}

static PyObject *frozen_memory_page_size(PyObject *self, PyObject *Py_UNUSED(ignored)) {
    return PyLong_FromSize_t(get_page_size());
}


/* ================================================================
 * Module definition
 * ================================================================ */

static PyMethodDef frozen_memory_methods[] = {
    {"freeze", frozen_memory_freeze, METH_VARARGS,
     "freeze(data: bytes) -> FrozenBuffer\n"
     "Copy data into a dedicated memory page and mark it read-only."},
    {"verify", frozen_memory_verify, METH_VARARGS,
     "verify(buffer: FrozenBuffer, expected_hash: bytes) -> bool\n"
     "Verify buffer contents against SHA-256 hash."},
    {"is_protected", frozen_memory_is_protected, METH_VARARGS,
     "is_protected(buffer: FrozenBuffer) -> bool\n"
     "Check if the memory page is still marked read-only."},
    {"destroy", frozen_memory_destroy, METH_VARARGS,
     "destroy(buffer: FrozenBuffer) -> None\n"
     "Securely wipe and free the memory page."},
    {"page_size", frozen_memory_page_size, METH_NOARGS,
     "page_size() -> int\n"
     "Return the OS memory page size in bytes."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef frozen_memory_module = {
    PyModuleDef_HEAD_INIT,
    "frozen_memory",
    "OS-level hardware memory protection for FrozenNamespace.\n\n"
    "Allocates dedicated memory pages and marks them read-only at the\n"
    "OS level. Any write attempt triggers SIGSEGV/ACCESS_VIOLATION.\n\n"
    "Part of the Sovereign Shield MCP Security Architecture.\n"
    "Copyright (c) 2026 Mattijs Moens.",
    -1,
    frozen_memory_methods
};

PyMODINIT_FUNC PyInit_frozen_memory(void) {
    PyObject *m;

    if (PyType_Ready(&FrozenBufferType) < 0)
        return NULL;

    m = PyModule_Create(&frozen_memory_module);
    if (m == NULL)
        return NULL;

    Py_INCREF(&FrozenBufferType);
    if (PyModule_AddObject(m, "FrozenBuffer", (PyObject *)&FrozenBufferType) < 0) {
        Py_DECREF(&FrozenBufferType);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}
