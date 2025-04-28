/* C pointer type, a subtype of int */

#include "Python.h"
#include "cpython/longintrepr.h"
#include "pointerobject.h"

#ifdef __CHERI_PURE_CAPABILITY__
#include <cheriintrin.h>
#endif

/* The type object for C pointers.  Note that this cannot be subclassed! */
typedef struct {
	PyObject_HEAD
/* TODO: store the type of the pointer + whether it's valid? */
	void* pointer;
	//PyObject *keeper;
} PyNativePointerObject;

PyTypeObject *c_void_p_type = NULL;

/* Methods */
static PyObject *
pointer_richcompare(PyObject *self, PyObject *other, int op)
{
	int result;
	uintptr_t a;
	uintptr_t b;

	if (self == other)
		Py_RETURN_RICHCOMPARE(0, 0, op);

	/* TODO: ?
	 * Not an integer;  try to use __index__ to convert:
	 * if (PyIndex_Check(v)) {
	 *   v = PyNumber_Index(v);
	 */

	/* Allow comparisons against longs with the same value: */
	if (PyNativePointer_Check(self))
		a = (uintptr_t)PyNativePointer_AsVoidPointer(self);
	else if (PyLong_Check(self))
		a = (uintptr_t)PyLong_AsPyAddr(self);
	else
		Py_RETURN_NOTIMPLEMENTED;

	if (PyNativePointer_Check(other))
		b = (uintptr_t)PyNativePointer_AsVoidPointer(other);
	else if (PyLong_Check(other))
		b = (uintptr_t)PyLong_AsPyAddr(other);
	else
		Py_RETURN_NOTIMPLEMENTED;

	if ((uintptr_t)a == (uintptr_t)b)
		result = 0;
	else
		result = a < b ? -1 : 1;
	Py_RETURN_RICHCOMPARE(result, 0, op);
}

static Py_hash_t
pointer_hash(PyObject *v)
{
	assert(PyNativePointer_CheckExact(v));
	return _Py_HashPointer(((PyNativePointerObject *)v)->pointer);
}

static int
pointer_bool(PyObject *v)
{
	assert(PyNativePointer_CheckExact(v));
	return ((PyNativePointerObject *)v)->pointer != NULL;
}

static PyObject *
pointer_int(PyObject *v)
{
	assert(PyNativePointer_CheckExact(v));
	PyNativePointerObject *cp = (PyNativePointerObject *)v;
	return PyLong_FromPyAddr((Py_addr_t)cp->pointer);
}

static PyObject *
pointer_repr(PyObject *v)
{
	assert(PyNativePointer_CheckExact(v));
	PyNativePointerObject *cp = (PyNativePointerObject *)v;

	/* print CHERI permissions */
#ifdef __CHERI_PURE_CAPABILITY__
	if (!cheri_tag_get(cp->pointer)){
		PyErr_Format(PyExc_TypeError, 
				"%s: a valid pointer or a null pointer is required, got %p", 
						__func__, cp->pointer); 
	}
	uintptr_t addr  = cheri_address_get(cp->pointer);
	size_t len = cheri_length_get(cp->pointer);
	uintptr_t base  = cheri_base_get(cp->pointer);
	uintptr_t top  = base + len;
	//size_t    off   = cheri_offset_get(cp->pointer);
    _Bool tag   = cheri_tag_get(cp->pointer);

	size_t      perms = cheri_perms_get(cp->pointer);
	char pstr[6];
	int  pi = 0;
	if (perms & CHERI_PERM_LOAD)      pstr[pi++] = 'r';
	if (perms & CHERI_PERM_STORE)     pstr[pi++] = 'w';
	if (perms & CHERI_PERM_LOAD_CAP)  pstr[pi++] = 'R';
	if (perms & CHERI_PERM_STORE_CAP) pstr[pi++] = 'L';
	if (perms & CHERI_PERM_EXECUTE)   pstr[pi++] = 'x';
	pstr[pi] = '\0';

	PyObject *res = PyUnicode_FromFormat(
			" [%s,0x%016x-0x%016x] 0x%016x",
			pstr,
			(uintptr_t)base,
			(uintptr_t)top,
			(uintptr_t)addr
			);
	return res;
#else
	return PyUnicode_FromFormat("<native pointer:%p> ", cp->pointer);
#endif

}


static PyNumberMethods pointer_as_number = {
	.nb_bool = pointer_bool,
	.nb_int = pointer_int,
	.nb_index = pointer_int,
};

static PyObject *
pointer_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	PyObject *source;
	PyNativePointerObject *self = (PyNativePointerObject *) type->tp_alloc(type, 0);
	
	if (self != NULL) {
		if (!PyArg_ParseTuple(args, "O:pointer", &source)){
			self->pointer = NULL;
			//self->keeper = NULL;
		} else {
		#ifdef __CHERI_PURE_CAPABILITY__
			if (!cheri_tag_get(source)) {
				PyErr_Format(PyExc_TypeError,
						"%s: a valid pointer or a null pointer is required, got %p", 
						__func__, source);
				return NULL;
			}
		#endif
			//self->keeper = source;
			self->pointer = (void *) source;
			//Py_INCREF(self);

			fprintf(stderr, "source addr %p\n", source);
		}
		return (PyObject *) self;

	}
	return NULL;
}

static void
pointer_dealloc(PyObject *obj)
{
	PyNativePointerObject *self = (PyNativePointerObject *)obj;
	// fprintf(stderr, "releasing c pointer %p\n", self->pointer);
	//Py_XDECREF(self->keeper);
	Py_TYPE(self)->tp_free((PyObject*)obj);
	//Py_TYPE(obj)->tp_free(obj);
}

static PyObject *
pointer_reduce(PyObject* self, PyObject *Py_UNUSED(ignored)) {
	PyErr_Format(PyExc_TypeError, "Attempting to pickle a native pointer (%p). "
			"This is a terrible idea and will not work on all systems!");
	return NULL;
}

static PyMethodDef pointer_methods[] = {
	{"__reduce__", (PyCFunction)pointer_reduce, METH_NOARGS,
		"Should not be called."},
	{NULL, NULL}  // sentinel
};

PyTypeObject _PyNativePointer_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_native_pointer",
	.tp_doc = "native pointer",
	.tp_basicsize = sizeof(PyNativePointerObject),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT, /* TODO: Py_TPFLAGS_LONG_SUBCLASS */
	.tp_richcompare = pointer_richcompare,
	.tp_repr = pointer_repr,
	.tp_new = pointer_new,
	.tp_dealloc = pointer_dealloc,
	.tp_hash = pointer_hash,
	.tp_as_number = &pointer_as_number,
	.tp_alloc = PyType_GenericAlloc,
	.tp_free = PyObject_Del,
	.tp_methods = pointer_methods,
};

static PyNativePointerObject _Py_NativeNullStruct = {
	PyObject_HEAD_INIT(&_PyNativePointer_Type)
		.pointer = NULL,
};
#define Py_NativeNULL ((PyObject*)(&_Py_NativeNullStruct))

PyObject *
PyNativePointer_FromVoidPointer(void* value) {
	PyNativePointerObject *p;
	/* Return the same instance for all NULL pointers: */
	if (value == NULL) {
		Py_INCREF(Py_NativeNULL);
		return Py_NativeNULL;
	}
#ifdef __CHERI_PURE_CAPABILITY__
	if (!__builtin_cheri_tag_get(value)) {
		PyErr_Format(PyExc_TypeError, "%s: a valid pointer or a NULL pointer is required, got %p", __func__, value);
		return NULL;
	}
#endif
	p = PyObject_New(PyNativePointerObject, &_PyNativePointer_Type);
	if (p == NULL)
		return NULL;
	p->pointer = value;
	return (PyObject *)p;
}

_Bool PyNativePointer_IsNull(PyObject* x) {
	/* Also allow NULL pointers */
	if (x == Py_None || x == Py_False)
		return 1;
	if (PyLong_Check(x))
		return _PyLong_Sign(x) == 0;
	/* TODO: do we need this fallback? */
#if 0
	/* Otherwise convert to long and check if the value is zero */
	PyObject * aslong = _PyLong_FromNbIndexOrNbInt(x);
	/* Ignore conversion errors */
	if (PyErr_Occurred())
		PyErr_Clear();
	if (aslong && _PyLong_Sign(aslong) == 0)
		return 1;
#endif
	return 0;
}

void *
PyNativePointer_AsVoidPointer(PyObject *vv)
{
	if (PyNativePointer_CheckExact(vv)) {
		// fprintf(stderr, "[DEBUG] AsVoidPointer: branch NATIVE_POINTER\n");
		assert(!PyErr_Occurred());
		return ((PyNativePointerObject*)vv)->pointer;
	}

	if (PyNativePointer_IsNull(vv)) {
		// fprintf(stderr, "[DEBUG] AsVoidPointer: branch NULL_POINTER\n");
		assert(!PyErr_Occurred());
		return NULL;
	}

	/* Handle the ctypes.c_void_p type: */
	if (c_void_p_type != NULL
			    && PyObject_TypeCheck(vv, (PyTypeObject*)c_void_p_type)){
		if (PyObject_HasAttrString(vv, "value")) {
			fprintf(stderr, "[DEBUG] AsVoidPointer: branch CTYPES.VALUE\n");
			PyObject* pv = PyObject_GetAttrString(vv, "value");
			if (pv == NULL)
				return NULL;
			/* We could also check that _type_ is "P" */
			if (PyNativePointer_CheckExact(pv)) {
				void* result = ((PyNativePointerObject*)pv)->pointer;
				Py_DECREF(pv);
				return result;
			}
			Py_DECREF(pv);
		}
	}
	// #ifdef WONT_WORK_ON_CHERI
	if (PyLong_Check(vv)){

		Py_addr_t addr = PyLong_AsPyAddr(vv);
		if (addr == (Py_addr_t)-1 && PyErr_Occurred())
			return NULL;

		fprintf(stderr, "[DEBUG] AsVoidPointer: branch PYLONG %p\n", (void *)(uintptr_t)addr);

		/* Probably not correct since it's not a valid capability on CHERI128... */
#ifdef __CHERI_PURE_CAPABILITY__
	if (!__builtin_cheri_tag_get((void *)(uintptr_t)addr)) {
		PyErr_Format(PyExc_TypeError, "%s: a valid pointer or a NULL pointer is required, got %p", __func__, vv);
		return NULL;
	}
#endif
		return (void*)(uintptr_t)addr;
			}
	// #else
	//fprintf(stderr, "[DEBUG] AsVoidPointer: branch TYPE_ERROR\n");

	PyErr_Format(PyExc_TypeError, "%s: a valid pointer or a NULL pointer is required, got %R", __func__, vv);
	return NULL;
	// #endif
}

PyObject *
PyNativePointer_FromUIntPtr(uintptr_t value) {
	/* A parallel to PyNativePointer_FromVoidPointer method, allowing */
	/* untagged uintptr_t, with the developer assuming the risks of this. */
	PyNativePointerObject *p;
	if (value == NULL) {
		Py_INCREF(Py_NativeNULL);
		return Py_NativeNULL;
	}
	/* Cheri validity tag check is skipped here, in constrast to FromVoidPointer method. */
	p = PyObject_New(PyNativePointerObject, &_PyNativePointer_Type);
	if (p == NULL)
		return NULL;
	p->pointer = (void *)value;
	return (PyObject *)p;
}

uintptr_t
PyNativePointer_AsUIntPtr(PyObject *vv)
{
	if (PyNativePointer_CheckExact(vv)) {
		assert(!PyErr_Occurred());
		return (uintptr_t)((PyNativePointerObject*)vv)->pointer;
	} else if (PyNativePointer_IsNull(vv)) {
		assert(!PyErr_Occurred());
		return (uintptr_t)NULL;
	}
	Py_addr_t addr = PyLong_AsPyAddr(vv);
	if (addr == (Py_addr_t)-1 && PyErr_Occurred())
		return (uintptr_t)NULL; /* XXX: or -1? */

	return (uintptr_t)addr;

}
