#include "globus_gsi_credential.h"

globus_result_t
globus_gsi_cred_has_private_key(globus_gsi_cred_handle_t handle,
                                int *has_private_key);

globus_result_t
globus_gsi_cred_verify_private_key(globus_gsi_cred_handle_t handle);

globus_result_t
globus_gsi_cred_get_goodafter(globus_gsi_cred_handle_t handle,
                              time_t *goodafter);

globus_result_t
globus_gsi_cred_get_chain_length(globus_gsi_cred_handle_t handle,
                                 int *length);
