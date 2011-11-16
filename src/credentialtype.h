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
    char loaded;
    char has_private_key;
} credential_Object;

PyObject *credential_new(PyTypeObject *type, PyObject *args, PyObject *kw);
void credential_dealloc(credential_Object *self);

int credential_init(credential_Object *self, PyObject *args, PyObject *kw);

PyObject *credential_load_cert(credential_Object *self, PyObject *args);
PyObject *credential_load_cert_file(credential_Object *self, PyObject *args);
PyObject *credential_load_cert_and_key(credential_Object *self,
                                       PyObject *args);
PyObject *credential_load_cert_and_key_file(credential_Object *self,
                                            PyObject *args);

PyObject *credential_validate(credential_Object *self, PyObject *args);

PyObject *credential_check_cert_issuer(credential_Object *self,
                                       PyObject *args);
PyObject *credential_check_private_key(credential_Object *self,
                                       PyObject *args);

PyObject *credential_get_identity(credential_Object *self, PyObject *args);
PyObject *credential_get_subject(credential_Object *self, PyObject *args);
PyObject *credential_get_issuer(credential_Object *self, PyObject *args);

PyObject *credential_get_lifetime(credential_Object *self, PyObject *args);
PyObject *credential_get_not_after(credential_Object *self, PyObject *args);
PyObject *credential_get_not_before(credential_Object *self, PyObject *args);

PyObject *credential_get_key_size(credential_Object *self, PyObject *args);
PyObject *credential_get_chain_length(credential_Object *self, PyObject *args);
PyObject *credential_has_private_key(credential_Object *self, PyObject *args);

#endif
