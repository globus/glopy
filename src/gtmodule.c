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

#include "globus_common.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_credential.h"
#include "globus_gss_assist.h"
#include "openssl/bn.h"

#include "exceptions.h"
#include "credentialtype.h"

PyObject *gt_error;

PyObject * deactivate_modules();

static PyMethodDef gt_module_methods[] = {
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
initgt(void) {
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

    m = Py_InitModule3("gt", gt_module_methods,
           "Module wrapping some Globus Toolkit features.");

    if (m == NULL)
        return;

    PyDateTime_IMPORT;

    if (!PyDateTimeAPI) {
        PyErr_SetString(PyExc_RuntimeError,
                        "Unable to import the datetime module.");
        return;
    }

    gt_error = PyErr_NewException("gt.error", NULL, NULL);
    Py_INCREF(gt_error);
    PyModule_AddObject(m, "error", gt_error);

    Py_INCREF(&credential_Type);
    PyModule_AddObject(m, "Credential", (PyObject *)&credential_Type);
}


PyObject *deactivate_modules(credential_Object *self, PyObject *args) {
	if (!PyArg_UnpackTuple(args, "gt.deactivate_modules", 0, 0)) {
		return NULL;
	}

    if (globus_module_deactivate_all() != GLOBUS_SUCCESS) {
        PyErr_SetString(gt_error, "No modules have been initialized");
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
PyObject *gt_PyDateTime_FromLong(long n) {
    PyObject *temp, *out;
    if ((temp = Py_BuildValue("(l)", n)) == NULL)
        return NULL;
    out = PyDateTime_FromTimestamp(temp);
    Py_DECREF(temp);
    return out;
}

void gt_set_error(globus_result_t result) {
    char *msg = globus_error_print_friendly(globus_error_peek(result));
    PyErr_SetString(gt_error, msg);
    free(msg);
}
