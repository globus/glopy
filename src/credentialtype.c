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

#include "globus_pre.h"
#include "globus_common.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_credential.h"
#include "globus_gss_assist.h"
#include "openssl/bn.h"
#include "openssl/x509.h"

#include "globus_gsi_cred_patch.h"

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
    self->has_private_key = 0;
    self->loaded = 0;

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

    self->has_private_key = 0;
    self->loaded = 1;

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

    self->has_private_key = 0;
    self->loaded = 1;

    Py_RETURN_NONE;
}


PyObject *
credential_load_cert_and_key(credential_Object *self, PyObject *args) {
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

    self->has_private_key = 1;
    self->loaded = 1;

    Py_RETURN_NONE;
}


PyObject *
credential_load_cert_and_key_file(credential_Object *self, PyObject *args) {
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

    self->has_private_key = 1;
    self->loaded = 1;

    Py_RETURN_NONE;
}


static inline int
check_loaded(credential_Object *self) {
    if (!self->loaded) {
        PyErr_SetString(glopy_error,
            "No credential has been loaded in this instance.");
        return 0;
    }
    return 1;
}


PyObject *
credential_get_identity(credential_Object *self, PyObject *args) {
    char *identity_name = NULL;
    globus_result_t result;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

    if (!check_loaded(self))
        return NULL;

    result = globus_gsi_cred_get_identity_name(self->handle, &identity_name);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    if (identity_name == NULL) {
        PyErr_SetString(glopy_error, "Got NULL string from gt");
        return NULL;
    }

    PyObject *out = PyString_FromString(identity_name);

    // See comment in globus_gsi_credential.c
    OPENSSL_free(identity_name);

    return out;
}


PyObject *
credential_get_subject(credential_Object *self, PyObject *args) {
    char *subject_name = NULL;
    globus_result_t result;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

    if (!check_loaded(self))
        return NULL;

    result = globus_gsi_cred_get_subject_name(self->handle, &subject_name);
    if (result != GLOBUS_SUCCESS) {
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

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

    if (!check_loaded(self))
        return NULL;

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

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

    if (!check_loaded(self))
        return NULL;

    result = globus_gsi_cred_get_lifetime(self->handle, &lifetime);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    return PyInt_FromLong(lifetime);
}


PyObject *
credential_get_not_after(credential_Object *self, PyObject *args) {
    time_t not_after;
    globus_result_t result;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

    if (!check_loaded(self))
        return NULL;

    result = globus_gsi_cred_get_goodtill(self->handle, &not_after);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    return glopy_PyDateTime_FromLong(not_after);
}


PyObject *
credential_get_not_before(credential_Object *self, PyObject *args) {
    time_t not_before;
    globus_result_t result;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

    if (!check_loaded(self))
        return NULL;

    result = globus_gsi_cred_get_goodafter(self->handle, &not_before);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    return glopy_PyDateTime_FromLong(not_before);
}


PyObject *credential_validate(credential_Object *self, PyObject *args) {
    globus_result_t result;
    globus_gsi_callback_data_t callback_data = NULL;
    int error = 0;

	if (!PyArg_ParseTuple(args, "")) {
        error = 1;
        goto exit;
	}

    if (!check_loaded(self)) {
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
credential_check_cert_issuer(credential_Object *self, PyObject *args) {
    globus_result_t result;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

    if (!check_loaded(self))
        return NULL;

    result = globus_gsi_cred_verify(self->handle);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    Py_RETURN_NONE;
}


PyObject *
credential_check_private_key(credential_Object *self, PyObject *args) {
    globus_result_t result;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

    if (!check_loaded(self))
        return NULL;

    result = globus_gsi_cred_verify_private_key(self->handle);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    Py_RETURN_NONE;
}


PyObject *
credential_check_private_key2(credential_Object *self, PyObject *args) {
    // This implementation does not rely on breaking the encapsulation of
    // the credential library (or patches to GT), but it's less efficient
    // because it has to copy the cert and private key to get access.
    globus_result_t result;
    int error = 0;
    char openssl_message[256];
    unsigned long openssl_error = 0;
    EVP_PKEY *private_key = NULL;
    X509 *cert = NULL;

	if (!PyArg_ParseTuple(args, "")) {
        error = 1;
		goto exit;
	}

    if (!check_loaded(self)) {
        error = 1;
        goto exit;
    }

    if (!self->has_private_key) {
        error = 1;
        PyErr_SetString(glopy_error,
            "No private key in this credential instance.");
        goto exit;
    }

    // TODO: patch a verify_private_key function into the GT cred library,
    // to avoid this wasteful copying of the key and cert.

    result = globus_gsi_cred_get_key(self->handle, &private_key);
    if (result != GLOBUS_SUCCESS) {
        error = 1;
        glopy_set_gt_error(result);
        goto exit;
    }

    result = globus_gsi_cred_get_cert(self->handle, &cert);
    if (result != GLOBUS_SUCCESS) {
        error = 1;
        glopy_set_gt_error(result);
        goto exit;
    }

    if (!X509_check_private_key(cert, private_key)) {
        error = 1;
        openssl_error = ERR_get_error();
        ERR_error_string_n(openssl_error, openssl_message,
                           sizeof(openssl_message));
        PyErr_SetString(glopy_error, openssl_message);
    }

 exit:
    if (private_key != NULL)
        EVP_PKEY_free(private_key);
    if (cert != NULL)
        X509_free(cert);

    if (error)
        return NULL;

    Py_RETURN_NONE;
}


PyObject *
credential_get_key_size(credential_Object *self, PyObject *args) {
    globus_result_t result;
    int bits;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

    if (!check_loaded(self))
        return NULL;

    result = globus_gsi_cred_get_key_bits(self->handle, &bits);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    return PyInt_FromLong(bits);
}


PyObject *
credential_get_chain_length(credential_Object *self, PyObject *args) {
    globus_result_t result;
    int chain_length;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

    if (!check_loaded(self))
        return NULL;

    result = globus_gsi_cred_get_chain_length(self->handle, &chain_length);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    return PyInt_FromLong(chain_length);
}


PyObject *
credential_has_private_key(credential_Object *self, PyObject *args) {
    globus_result_t result;
    int has_private_key;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

    if (!check_loaded(self))
        return NULL;

    result = globus_gsi_cred_has_private_key(self->handle, &has_private_key);
    if (result != GLOBUS_SUCCESS) {
        glopy_set_gt_error(result);
        return NULL;
    }

    return PyBool_FromLong(has_private_key);
}
