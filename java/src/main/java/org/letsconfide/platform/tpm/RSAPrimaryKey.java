package org.letsconfide.platform.tpm;

import tss.Tpm;
import tss.tpm.*;

/**
 * Represents an RSA primary key on the TPM, used for securing a storage key.
 * The constructed primary key is attached to the storage hierarchy of the TPM.
 * RSA padding used is OAEP.
 */
public class RSAPrimaryKey extends TPMKey
{
    private final TPM_HANDLE keyHandle;

    /**
     * @param size The key size, 1024 or 2048
     * @param tpm The TPM
     */
    RSAPrimaryKey(Tpm tpm, int size)
    {
        super(tpm);
        TPMT_PUBLIC template = new TPMT_PUBLIC(
                TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.restricted, TPMA_OBJECT.decrypt, TPMA_OBJECT.fixedTPM, TPMA_OBJECT.userWithAuth, TPMA_OBJECT.fixedParent, TPMA_OBJECT.noDA, TPMA_OBJECT.sensitiveDataOrigin),
                new byte[0],
                new TPMS_RSA_PARMS( new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB), new TPMS_NULL_ASYM_SCHEME(), size, 65537),
                new TPM2B_PUBLIC_KEY_RSA());

        // Sensitive data unnecessary for the primary key. Appropriate safeguards are in the storage key.
        TPMS_SENSITIVE_CREATE sens = new TPMS_SENSITIVE_CREATE(new byte[0], new byte[0]);
        CreatePrimaryResponse cRes = tpm.CreatePrimary(TPM_HANDLE.from(TPM_RH.OWNER), sens, template, new byte[0], new TPMS_PCR_SELECTION[0]);
        keyHandle = cRes.handle;
    }

    @Override
    public TPM_HANDLE getKeyHandle()
    {
        return keyHandle;
    }

}
