/*
 * Copyright 2011 University of Chicago
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
/* Python wrapper around parts of Globus Toolkit.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <datetime.h>

#include "globus_pre.h"
#include "globus_common.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_credential.h"
#include "globus_gss_assist.h"
#include "openssl/bn.h"

#include "exceptions.h"
#include "credentialtype.h"

PyObject *glopy_error;

PyObject * deactivate_modules();

static PyMemberDef credential_members[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef credential_methods[] = {
    {"load_cert", (PyCFunction)credential_load_cert, METH_VARARGS,
     "Load a certificate (with optional chain) from a PEM string."},
    {"load_cert_file", (PyCFunction)credential_load_cert_file, METH_VARARGS,
     "Load a certificate (with optional chain) from a file in PEM format."},
    {"load_cert_and_key", (PyCFunction)credential_load_cert_and_key,
     METH_VARARGS,
     "Load a certificate and private key (with optional chain) from a"
     " PEM string."},
    {"load_cert_and_key_file", (PyCFunction)credential_load_cert_and_key_file,
     METH_VARARGS,
     "Load a certificate and private key (with optional chain) from a file,"
     " in PEM format."},
    {"validate", (PyCFunction)credential_validate, METH_VARARGS,
     "Determine if the certificate is valid using the GT configured"
     " CA certificate directory. Signing policies are checked"
     " for each non-proxy link in the chain. Returns None on success, raises"
     " glopy.error on failure."},
    {"check_cert_issuer", (PyCFunction)credential_check_cert_issuer,
     METH_VARARGS,
     "Check that the main certificate is signed by the public key of the"
     " first certificate in the chain (it's issuer). Does not check signing"
     " policies. Returns None on success, raises glopy.error on failure."},
    {"check_private_key", (PyCFunction)credential_check_private_key,
     METH_VARARGS, "Check that the private key matches the public key in"
     " the main certificate. Only works on credentials containing a private"
     " key. Returns None on success, raises glopy.error on failure."},
    {"get_identity", (PyCFunction)credential_get_identity, METH_VARARGS,
     "Get the identity subject of the certificate, as a string in openssl "
     "format. This is the subject with proxy CNs removed, "
     "and should usually be used instead of the subject." },
    {"get_subject", (PyCFunction)credential_get_subject, METH_VARARGS,
     "Get the subject of the certificate, as a string in openssl format."},
    {"get_issuer", (PyCFunction)credential_get_issuer, METH_VARARGS,
     "Get the issuer of the certificate, as a string in openssl format."},
    {"get_lifetime", (PyCFunction)credential_get_lifetime, METH_VARARGS,
     "Get the remaining valid lifetime of the certificate in seconds."},
    {"get_not_after", (PyCFunction)credential_get_not_after, METH_VARARGS,
     "Get the time the credential expires, as a datetime object in UTC."
     " This will be the smallest expire time of the main certificate"
     " and any certificates in the chain."},
    {"get_not_before", (PyCFunction)credential_get_not_before, METH_VARARGS,
     "Get the not before time of the credential, as a datetime object in UTC."
     " This will be the largest not before time of the main certificate"
     " and any certificates in the chain."},
    {"get_key_size", (PyCFunction)credential_get_key_size, METH_VARARGS,
     "Get the key size in bits."},
    {"get_chain_length", (PyCFunction)credential_get_chain_length,
     METH_VARARGS,
     "Get the length of the certificate chain, not including the main"
     " certificate."},
    {"has_private_key", (PyCFunction)credential_has_private_key, METH_VARARGS,
     "True if a credential has been loaded and includes a private key."},
    {NULL}  /* Sentinel */
};

static PyTypeObject credential_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "glopy.Credential",        /*tp_name*/
    sizeof(credential_Object), /*tp_basicsize*/
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
    "Class for loading and verifying X509 credentials."
    " A credential must contain a certificate, and may optionally contain"
    " a private key and/or additional certificates making up the trust chain."
    " The typical example is a proxy credential, which will contain a"
    " proxy certificate, a private key, and the end entity certificate"
    " that issued the proxy. Some methods apply only if a chain and/or"
    " private key is present, and will raise an error if those fields"
    " are not present. The functionality is implemented using the credential"
    " library from globus toolkit. The constructor takes an optional string"
    " parameter, which is equivalent to using load_cert. If not string is"
    " passed, one of the load methods must be called before using any of"
    " the methods are called, otherwise an exception is thrown."
    , /* tp_doc */
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

static PyMethodDef glopy_module_methods[] = {
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
initglopy(void) {
    PyObject *m;

    if (PyType_Ready(&credential_Type) < 0)
        return;

    globus_module_descriptor_t *modules[] =
    {
        GLOBUS_COMMON_MODULE,
        GLOBUS_GSI_SYSCONFIG_MODULE,
        GLOBUS_GSI_CREDENTIAL_MODULE,
        GLOBUS_GSI_CALLBACK_MODULE,
        NULL
    };

    globus_module_descriptor_t *failed_module;
    int rc = globus_module_activate_array(modules, &failed_module);
    if (rc != GLOBUS_SUCCESS) {
        return;
    }

    m = Py_InitModule3("glopy", glopy_module_methods,
           "Module wrapping some Globus Toolkit features.");

    if (m == NULL)
        return;

    PyDateTime_IMPORT;

    if (!PyDateTimeAPI) {
        PyErr_SetString(PyExc_RuntimeError,
                        "Unable to import the datetime module.");
        return;
    }

    glopy_error = PyErr_NewException("glopy.error", NULL, NULL);
    Py_INCREF(glopy_error);
    PyModule_AddObject(m, "error", glopy_error);

    Py_INCREF(&credential_Type);
    PyModule_AddObject(m, "Credential", (PyObject *)&credential_Type);
}


PyObject *deactivate_modules(credential_Object *self, PyObject *args) {
	if (!PyArg_UnpackTuple(args, "glopy.deactivate_modules", 0, 0)) {
		return NULL;
	}

    if (globus_module_deactivate_all() != GLOBUS_SUCCESS) {
        PyErr_SetString(glopy_error, "No modules have been initialized");
        return NULL;
    }

    Py_RETURN_NONE;
}

/*
 * This is used to get around the awkard datetime C-API, which
 * requires a static variable to be set with PyDateTime_IMPORT. The
 * natural place to put this is in module init, but the credential type
 * is in a separate source file and has no natural place for one time
 * initialization. We call out to this module level function instead.
 */
PyObject *glopy_PyDateTime_FromLong(long n) {
    PyObject *temp, *out;
    if ((temp = Py_BuildValue("(l)", n)) == NULL)
        return NULL;
    out = PyDateTime_FromTimestamp(temp);
    Py_DECREF(temp);
    return out;
}

void glopy_set_gt_error(globus_result_t result) {
    char *msg = globus_error_print_friendly(globus_error_peek(result));
    PyErr_SetString(glopy_error, msg);
    free(msg);
}
