package org.letsconfide.platform.tpm;

import org.letsconfide.LetsConfideException;
import tss.Tpm;
import tss.tpm.*;

import javax.annotation.CheckForNull;
import java.util.ArrayList;
import java.util.List;

import static org.letsconfide.config.ConfigHeaders.HashType.SHA256;

/**
 * Ephemeral AES key based on the TPM, used for key encryption.
 * The constructed key is a primary key attached to the null hierarchy of the TPM.
 * The AES mode of operation is CFB (Cipher Feedback).
 */
public class AesEphemeralKey extends TPMKey implements TpmKeyEncryptionKey
{
    private final List<byte[]> tokens;
    // Delegates to an AES primary key using the NULL hierarchy in the TPM.
    private final TPM_HANDLE keyHandle;
    private final byte[] iv;

    /**
     * Instantiates a new {@link AesEphemeralKey} by generating a new key if the token list is null,
     * or by reconstituting a key using the given token list.
     * @param keySize The key size, 128 or 256
     * @param tpm The TPM
     * @param tokenList List of external tokens
     */
    AesEphemeralKey(int keySize, Tpm tpm, @CheckForNull List<byte[]> tokenList)
    {
        super(tpm);
        if(tokenList == null)
        {
            tokens = new ArrayList<>(3);
            // Initialization vector, size is equals to the AES block size.
            tokens.add(TpmUtils.randomBytes(tpm, 16));
            // Optimal size for authValue is the nameHash size of the TPM object being created
            tokens.add(TpmUtils.randomBytes(tpm, SHA256.getNumBits()/8));
            // Secret data must equal the key size
            tokens.add(TpmUtils.randomBytes(tpm, keySize/8));
        }
        else
        {
            if(tokenList.size() != 3)
            {

                // FIXME: Cause this failure and ensure proper cleanup.
                throw new LetsConfideException("Could not reconstitute ephemeral key invalid number of tokens "+tokenList.size());
            }
            this.tokens = tokenList;
        }
        // Initialization vector for AES_FSB mode.
        this.iv = tokens.get(0);
        byte[] authValue = tokens.get(1);
        byte[] secretData = tokens.get(2);
        TPMS_SENSITIVE_CREATE sensitive = new TPMS_SENSITIVE_CREATE(authValue, secretData);
        CreatePrimaryResponse cRes = tpm.CreatePrimary(TPM_HANDLE.from(TPM_RH.NULL), sensitive, getPrimaryTemplate(keySize), new byte[0],
                new TPMS_PCR_SELECTION[]{new TPMS_PCR_SELECTION(TPM_ALG_ID.SHA256, new byte[]{1, 0, 0})});
        keyHandle = cRes.handle;
        keyHandle.AuthValue = authValue;
    }

    private static TPMT_PUBLIC getPrimaryTemplate(int size) {
        return new TPMT_PUBLIC(
                TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.encrypt, TPMA_OBJECT.decrypt, TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.userWithAuth),
                new byte[0],
                new TPMS_SYMCIPHER_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, size, TPM_ALG_ID.CFB)),
                new TPM2B_DIGEST_SYMCIPHER());
    }

    @Override
    public List<byte[]> getTokens()
    {
        return tokens;
    }

    @Override
    public TPM_HANDLE getKeyHandle()
    {
        return keyHandle;
    }

    public byte[] wrap(byte[] dek)
    {
        return new WrapUnwrapHandler().wrap(dek);
    }

    public byte[] unwrap(byte[] encryptedDek)
    {
        return new WrapUnwrapHandler().unwrap(encryptedDek);
    }

    private class WrapUnwrapHandler extends AESWrapUnwrapHandler
    {

        WrapUnwrapHandler()
        {
            super(getTpm(), keyHandle);
        }
        @Override
        byte[] doWrap(byte[] iv, byte[] dek)
        {
            return getTpm().EncryptDecrypt(getKeyHandle(), (byte) 0, TPM_ALG_ID.CFB, iv, dek).outData;
        }

        @Override
        byte[] doUnwrap(byte[] iv, byte[] wrappedDek)
        {
            return getTpm().EncryptDecrypt(getKeyHandle(), (byte) 1, TPM_ALG_ID.CFB, iv, wrappedDek).outData;
        }
    }
}
