/* C pointer object interface */

#ifndef Py_CPOINTEROBJECT_H
#define Py_CPOINTEROBJECT_H

#include "longobject.h"

#ifdef __cplusplus
extern "C" {
#endif


PyAPI_DATA(PyTypeObject) _PyNativePointer_Type;
#define PyNativePointer_CheckExact(x) (Py_TYPE(x) == &_PyNativePointer_Type)
#define PyNativePointer_Check(x) (PyNativePointer_CheckExact(x) || PyNativePointer_IsNull(x))

PyAPI_FUNC(_Bool) PyNativePointer_IsNull(PyObject *);
PyAPI_FUNC(PyObject *) PyNativePointer_FromVoidPointer(void *);
PyAPI_FUNC(void *) PyNativePointer_AsVoidPointer(PyObject *);
PyAPI_FUNC(PyObject *) PyNativePointer_FromUIntPtr(uintptr_t);
PyAPI_FUNC(uintptr_t) PyNativePointer_AsUIntPtr(PyObject *);

#ifdef __cplusplus
}
#endif
#endif /* !Py_CPOINTEROBJECT_H */
