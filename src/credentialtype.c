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
/* Python wrapper around globus_gsi_credential.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <time.h>

#include "exceptions.h"

#include "globus_common.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_credential.h"
#include "globus_gss_assist.h"
#include "openssl/bn.h"

#include "credentialtype.h"
#include "glopymodule.h"

void
credential_dealloc(credential_Object *self) {
    if (self->handle != NULL)
        globus_gsi_cred_handle_destroy(self->handle);
    if (self->cert_dir != NULL)
        free(self->cert_dir);
    self->ob_type->tp_free((PyObject*)self);
}

PyObject *
credential_new(PyTypeObject *type, PyObject *args, PyObject *kw) {
    credential_Object *self;

    globus_result_t result;

    self = (credential_Object *)type->tp_alloc(type, 0);

    self->handle = NULL;
    self->cert_dir = NULL;

    // TODO: get cert_dir once in module init.
    result = GLOBUS_GSI_SYSCONFIG_GET_CERT_DIR(&self->cert_dir);
    if (result != GLOBUS_SUCCESS) {
        if (self->cert_dir != NULL) {
            free(self->cert_dir);
            self->cert_dir = NULL;
        }
        glopy_set_gt_error(result);
        return NULL;
    }

    result = globus_gsi_cred_handle_init(&self->handle, NULL);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    return (PyObject *)self;
}

PyObject *
load_cert(credential_Object *self, const char *pem_string) {
    BIO *cert_bio = NULL;
    globus_result_t result;

    if((cert_bio = BIO_new_mem_buf((void *)pem_string, -1)) == NULL) {
        PyErr_SetString(glopy_error, "Failed to create BIO for string data");
        return NULL;
    }

    result = globus_gsi_cred_read_cert_bio(self->handle, cert_bio);

    if (cert_bio != NULL) {
        BIO_free(cert_bio);
    }

    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    Py_RETURN_NONE;
}

int
credential_init(credential_Object *self, PyObject *args, PyObject *kw) {
    char *pem_string = NULL;
    PyObject *tmp = NULL;

	if (!PyArg_ParseTuple(args, "|s", &pem_string)) {
		return -1;
	}

    if (pem_string == NULL) {
        return 0;
    }

    tmp = load_cert(self, pem_string);
    if (tmp == NULL) {
        return -1;
    } else {
        Py_DECREF(tmp);
    }

    return 0;
}

PyObject *
credential_load_cert(credential_Object *self, PyObject *args) {
    char *pem_string;

	if (!PyArg_ParseTuple(args, "s", &pem_string)) {
		return NULL;
	}

    return load_cert(self, pem_string);
}

PyObject *
credential_load_cert_file(credential_Object *self, PyObject *args) {
    char *file_name;
    globus_result_t result;

	if (!PyArg_ParseTuple(args, "s", &file_name)) {
		return NULL;
	}

    result = globus_gsi_cred_read_cert(self->handle, file_name);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    Py_RETURN_NONE;
}

PyObject *
credential_load_proxy(credential_Object *self, PyObject *args) {
    const char *pem_string = NULL;
    BIO *proxy_bio = NULL;
    globus_result_t result;

	if (!PyArg_ParseTuple(args, "s", &pem_string)) {
		return NULL;
	}

    if((proxy_bio = BIO_new_mem_buf((void *)pem_string, -1)) == NULL) {
        PyErr_SetString(glopy_error, "Failed to create BIO for string data");
        return NULL;
    }

    result = globus_gsi_cred_read_proxy_bio(self->handle, proxy_bio);

    if (proxy_bio != NULL) {
        BIO_free(proxy_bio);
    }

    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    Py_RETURN_NONE;
}

PyObject *
credential_load_proxy_file(credential_Object *self, PyObject *args) {
    const char *file_name;
    globus_result_t result;

	if (!PyArg_ParseTuple(args, "s", &file_name)) {
		return NULL;
	}

    result = globus_gsi_cred_read_proxy(self->handle, file_name);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    Py_RETURN_NONE;
}

PyObject *
credential_get_identity(credential_Object *self, PyObject *args) {
    char *subject_name = NULL;
    globus_result_t result;

	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}

    result = globus_gsi_cred_get_identity_name(self->handle, &subject_name);
    if (result != GLOBUS_SUCCESS) {
        // TODO: this assumes that subject_name was not allocated on
        // failure - is this always correct?
        glopy_set_gt_error(result);
        return NULL;
    }

    if (subject_name == NULL) {
        PyErr_SetString(glopy_error, "Got NULL string from gt");
        return NULL;
    }

    PyObject *out = PyString_FromString(subject_name);

    // See comment in globus_gsi_credential.c
    OPENSSL_free(subject_name);

    return out;
}

PyObject *
credential_get_subject(credential_Object *self, PyObject *args) {
    char *subject_name = NULL;
    globus_result_t result;

	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}

    result = globus_gsi_cred_get_subject_name(self->handle, &subject_name);
    if (result != GLOBUS_SUCCESS) {
        // TODO: this assumes that subject_name was not allocated on
        // failure - is this always correct?
        glopy_set_gt_error(result);
        return NULL;
    }

    if (subject_name == NULL) {
        PyErr_SetString(glopy_error, "Got NULL string from gt");
        return NULL;
    }

    PyObject *out = PyString_FromString(subject_name);

    // See comment in globus_gsi_credential.c
    OPENSSL_free(subject_name);

    return out;
}

PyObject *
credential_get_issuer(credential_Object *self, PyObject *args) {
    char *issuer_name = NULL;
    globus_result_t result;

	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}

    result = globus_gsi_cred_get_issuer_name(self->handle, &issuer_name);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    if (issuer_name == NULL) {
        PyErr_SetString(glopy_error, "Got NULL string from gt");
        return NULL;
    }

    PyObject *out = PyString_FromString(issuer_name);

    // See comment in globus_gsi_credential.c
    OPENSSL_free(issuer_name);

    return out;
}

PyObject *
credential_get_lifetime(credential_Object *self, PyObject *args) {
    time_t lifetime;
    globus_result_t result;

	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}

    result = globus_gsi_cred_get_lifetime(self->handle, &lifetime);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    return PyInt_FromLong(lifetime);
}

PyObject *
credential_get_goodtill(credential_Object *self, PyObject *args) {
    time_t goodtill;
    globus_result_t result;

	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}

    result = globus_gsi_cred_get_goodtill(self->handle, &goodtill);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    return glopy_PyDateTime_FromLong(goodtill);
}

PyObject *credential_verify_chain(credential_Object *self, PyObject *args) {
    globus_result_t result;
    globus_gsi_callback_data_t callback_data = NULL;
    int error = 0;

	if (!PyArg_ParseTuple(args, "")) {
        error = 1;
        goto exit;
	}

    result = globus_gsi_callback_data_init(&callback_data);
    if (result != GLOBUS_SUCCESS) {
        error = 1;
        glopy_set_gt_error(result);
        goto exit;
    }

    result = globus_gsi_callback_set_cert_dir(callback_data,
                                              self->cert_dir);
    if (result != GLOBUS_SUCCESS) {
        error = 1;
        glopy_set_gt_error(result);
        goto exit;
    }

    result = globus_gsi_callback_set_check_policy_for_self_signed_certs(
                                                callback_data, GLOBUS_FALSE);
    if (result != GLOBUS_SUCCESS) {
        error = 1;
        glopy_set_gt_error(result);
        goto exit;
    }

    result = globus_gsi_cred_verify_cert_chain(self->handle, callback_data);

    if (result != GLOBUS_SUCCESS) {
        error = 1;
        glopy_set_gt_error(result);
        goto exit;
    }

 exit:

    if (callback_data != NULL)
        globus_gsi_callback_data_destroy(callback_data);

    if (error)
        return NULL;

    Py_RETURN_NONE;
}

PyObject *
credential_verify_keys(credential_Object *self, PyObject *args) {
    globus_result_t result;

	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}

    result = globus_gsi_cred_verify(self->handle);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    Py_RETURN_NONE;
}

PyObject *credential_get_key_bits(credential_Object *self, PyObject *args) {
    globus_result_t result;
    int bits;

	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}

    result = globus_gsi_cred_get_key_bits(self->handle, &bits);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    return PyInt_FromLong(bits);
}
