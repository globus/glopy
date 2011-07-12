
#include "globus_i_gsi_credential.h"
#include "globus_gsi_cred_patch.h"

/**
 * @ingroup globus_gsi_cred_handle
 * Check that the private key is present and matches the public key in the
 * cert.
 *
 * @param handle
 *        The credential handle containing the cert and key to be verified.
 *
 * @return
 *        GLOBUS_SUCCESS if no error, otherwise an error object
 *        identifier is returned
 */
globus_result_t
globus_gsi_cred_verify_private_key(
    globus_gsi_cred_handle_t            handle)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ = 
        "globus_gsi_cred_verify_private_key";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle passed to function: %s"), _function_name_));
        goto exit;
    }

    if (handle->key == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_PRIVATE_KEY,
            (_GCRSL("The handle's key is NULL")));

        goto exit;
    }

    if (handle->cert == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_PRIVATE_KEY,
            (_GCRSL("The handle's cert is NULL")));

        goto exit;
    }

    if (!X509_check_private_key(handle->cert, handle->key)) {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_PRIVATE_KEY,
            (_GCRSL("Failed to verify private key")));
    }

 exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}


/**
 * @ingroup globus_gsi_cred_handle
 * Check the credential handle contains a private key. Credentials loaded
 * with a read_proxy function should contain a key; those loaded with read_cert
 * should not contain a key.
 *
 * @param handle
 *        A credential handle that has been initialized and successfully
 *        loaded with a read function.
 *
 * @return
 *        GLOBUS_SUCCESS if a private key is present,
 *        otherwise an error object identifier is returned
 */
globus_result_t
globus_gsi_cred_has_private_key(
    globus_gsi_cred_handle_t            handle,
    int *                               has_private_key)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_cred_has_private_key";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle passed to function: %s"), _function_name_));
        goto exit;
    }

    if(has_private_key == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL has_private_key parameter passed to function: %s"),
             _function_name_));
        goto exit;
    }

    *has_private_key = (handle->key != NULL);

 exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}

/*
 * @ingroup globus_gsi_cred_handle
 * Get the number of certificates in the chain not including the main
 * certificate.
 *
 * @param handle
 *      A credential handle that has been initialized and successfully
 *      loaded with a read function.
 *
 * @return
 *      GLOBUS_SUCCESS if no error, otherwise an error
 *      object identifier is returned
 */
globus_result_t
globus_gsi_cred_get_chain_length(
    globus_gsi_cred_handle_t            handle,
    int *                               length)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_chain_length";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle passed to function: %s"), _function_name_));
        goto exit;
    }

    if(length == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL length parameter passed to function: %s"), _function_name_));
        goto exit;
    }

    if (handle->cert_chain == NULL)
    {
        *length = 0;
    }
    else
    {
        *length = sk_X509_num(handle->cert_chain);
    }

 exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}


/**
 * @ingroup globus_gsi_cred_handle
 * Get the not before time of the credential, which is the latest not before
 * time of the certificate and each certificate in it's chain.
 *
 * @param handle
 *        The credential handle to retrieve the not before time from
 * @param goodafter
 *        Contains the not before time if GLOBUS_SUCCESS is returned
 *
 * @return
 *        GLOBUS_SUCCESS if no error, otherwise an error object
 *        identifier is returned
 */
globus_result_t
globus_gsi_cred_get_goodafter(
    globus_gsi_cred_handle_t            handle,
    time_t *                            goodafter)
{
    X509 *                              current_cert = NULL;
    time_t                              tmp_goodafter;
    int                                 cert_count = 0;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_goodafter";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL handle parameter passed to function: %s"),
             _function_name_));
        goto exit;
    }

    if(goodafter == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL goodafter parameter passed to function: %s"),
             _function_name_));
        goto exit;
    }

    if (handle->cert == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_PRIVATE_KEY,
            (_GCRSL("The handle's cert is NULL")));

        goto exit;
    }

    current_cert = handle->cert;

    *goodafter = 0;
    tmp_goodafter = 0;

    if(handle->cert_chain)
    {
        cert_count = sk_X509_num(handle->cert_chain);
    }

    while(current_cert)
    {
        result = globus_gsi_cert_utils_make_time(
            X509_get_notBefore(current_cert),
            &tmp_goodafter);
        if(result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_WITH_CRED);
            goto exit;
        }

        if(*goodafter == 0 || tmp_goodafter > *goodafter)
        {
            *goodafter = tmp_goodafter;
        }

        if(handle->cert_chain && cert_count)
        {
            cert_count--;
            current_cert = sk_X509_value(
                handle->cert_chain,
                cert_count);
        }
        else
        {
            current_cert = NULL;
        }
    }

 exit:
    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
