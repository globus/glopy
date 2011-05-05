/* Copyright 2011 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <Python.h>
#include <structmember.h>

#ifndef CREDENTIALTYPE_H
#define CREDENTIALTYPE_H

typedef struct {
    PyObject_HEAD
    globus_gsi_cred_handle_t handle;
    char *cert_dir;
} credential_Object;

PyObject *credential_new(PyTypeObject *type, PyObject *args, PyObject *kw);
void credential_dealloc(credential_Object *self);

int credential_init(credential_Object *self, PyObject *args, PyObject *kw);

PyObject *credential_load_cert(credential_Object *self, PyObject *args);
PyObject *credential_load_cert_file(credential_Object *self, PyObject *args);
PyObject *credential_load_proxy(credential_Object *self, PyObject *args);
PyObject *credential_load_proxy_file(credential_Object *self, PyObject *args);

PyObject *credential_verify_chain(credential_Object *self, PyObject *args);
PyObject *credential_verify_keys(credential_Object *self, PyObject *args);

PyObject *credential_get_subject(credential_Object *self, PyObject *args);
PyObject *credential_get_issuer(credential_Object *self, PyObject *args);

PyObject *credential_get_lifetime(credential_Object *self, PyObject *args);
PyObject *credential_get_goodtill(credential_Object *self, PyObject *args);

PyObject *credential_get_key_bits(credential_Object *self, PyObject *args);

static PyMemberDef credential_members[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef credential_methods[] = {
    {"load_cert",  (PyCFunction)credential_load_cert, METH_VARARGS,
     "Load a certificate (with optional chain) from a PEM string."},
    {"load_cert_file",  (PyCFunction)credential_load_cert_file, METH_VARARGS,
     "Load a certificate (with optional chain) from a file in PEM format."},
    {"load_proxy",  (PyCFunction)credential_load_proxy, METH_VARARGS,
     "Load a proxy credential (with optional chain) from a PEM string."},
    {"load_proxy_file",  (PyCFunction)credential_load_proxy_file, METH_VARARGS,
     "Load a proxy credential (with optional chain) from a file,"
     " in PEM format."},
    {"verify_chain",  (PyCFunction)credential_verify_chain, METH_VARARGS,
     "Verify the certificate chain. Also checks the signing policies."
     " Returns None on success, raises gt.error on failure."},
    {"verify_keys",  (PyCFunction)credential_verify_keys, METH_VARARGS,
     "Verify that the public and private keys match."
     " Only works if for proxy credentials containing the private key"
     " and issuer certificate."
     " Returns None on success, raises gt.error on failure."},
    {"get_subject",  (PyCFunction)credential_get_subject, METH_VARARGS,
     "Get the subject of the certificate, as a string in openssl format."},
    {"get_issuer",  (PyCFunction)credential_get_issuer, METH_VARARGS,
     "Get the issuer of the certificate, as a string in openssl format."},
    {"get_lifetime",  (PyCFunction)credential_get_lifetime, METH_VARARGS,
     "Get the remaining valid lifetime of the certificate in seconds."},
    {"get_goodtill",  (PyCFunction)credential_get_goodtill, METH_VARARGS,
     "Get the time the certificate expires, as a datetime object in UTC."},
    {"get_key_bits",  (PyCFunction)credential_get_key_bits, METH_VARARGS,
     "Get the number of bits in the key."},
    {NULL}  /* Sentinel */
};

static PyTypeObject credential_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "gt.Credential",              /*tp_name*/
    sizeof(credential_Object),    /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    0,                         /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT |
      Py_TPFLAGS_BASETYPE,     /*tp_flags*/
    "Wrapper around a gt cred_handle",    /* tp_doc */
    0,		                   /* tp_traverse */
    0,		                   /* tp_clear */
    0,		                   /* tp_richcompare */
    0,		                   /* tp_weaklistoffset */
    0,		                   /* tp_iter */
    0,		                   /* tp_iternext */
    credential_methods,           /* tp_methods */
    credential_members,           /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)credential_init,    /* tp_init */
    0,                         /* tp_alloc */
    credential_new,               /* tp_new */
};

#endif
