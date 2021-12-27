package org.letsconfide.platform.tpm;

import tss.Tpm;
import tss.tpm.*;

/**
 * Represents an AES primary key on the TPM, used for securing a storage key.
 * The constructed primary key is attached to the storage hierarchy of the TPM.
 * The AES mode of operation is CFB (Cipher Feedback).
 */
public class AESPrimaryKey extends TPMKey
{
    private final TPM_HANDLE keyHandle;

    /**
     * @param keySize The key size, 128 or 256
     * @param tpm The TPM
     */
    AESPrimaryKey(int keySize, Tpm tpm)
    {
        this(keySize, tpm,
                // Storage hierarchy is used for typical
                TPM_HANDLE.from(TPM_RH.OWNER),
                // Sensitive data unnecessary for the primary key. Appropriate safeguards are in the storage key.
                new TPMS_SENSITIVE_CREATE(new byte[0], new byte[0]),
                new TPMA_OBJECT(TPMA_OBJECT.restricted, TPMA_OBJECT.decrypt, TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.userWithAuth, TPMA_OBJECT.sensitiveDataOrigin));
    }

    private AESPrimaryKey(int keySize, Tpm tpm, TPM_HANDLE hierarchy, TPMS_SENSITIVE_CREATE sens, TPMA_OBJECT parameters)
    {
        super(tpm);

        TPMT_PUBLIC template = new TPMT_PUBLIC(
                TPM_ALG_ID.SHA256,
                parameters,
                new byte[0],
                new TPMS_SYMCIPHER_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, keySize, TPM_ALG_ID.CFB)),
                new TPM2B_DIGEST_SYMCIPHER());

        CreatePrimaryResponse createPrimaryResponse = tpm.CreatePrimary(hierarchy, sens, template, new byte[0],  new TPMS_PCR_SELECTION[]{new TPMS_PCR_SELECTION(TPM_ALG_ID.SHA256, new byte[]{1, 0, 0})});
        this.keyHandle = createPrimaryResponse.handle;
    }

    @Override
    public TPM_HANDLE getKeyHandle()
    {
        return keyHandle;
    }

}
