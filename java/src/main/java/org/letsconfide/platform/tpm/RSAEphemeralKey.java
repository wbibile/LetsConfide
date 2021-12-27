package org.letsconfide.platform.tpm;

import org.letsconfide.LetsConfideException;
import tss.Tpm;
import tss.tpm.*;

import javax.annotation.CheckForNull;
import java.util.ArrayList;
import java.util.List;

import static org.letsconfide.config.ConfigHeaders.HashType.SHA256;
import static org.letsconfide.platform.tpm.TpmUtils.getRsaPaddingScheme;

/**
 * Ephemeral RSA key based on the TPM, used for key encryption.
 * The constructed key is a primary key attached to the null hierarchy of the TPM.
 * RSA padding used is OAEP.
 */
public class RSAEphemeralKey extends TPMKey implements TpmKeyEncryptionKey
{
    private final List<byte[]> tokens;
    private final TPM_HANDLE keyHandle;

    /**
     * Instantiates a new {@link RSAEphemeralKey} by generating a new key if the token list is null,
     * or by reconstituting a key using the given token list.
     * @param keySize The key size, 1024 or 2048
     * @param tpm The TPM
     * @param tokenList List of external tokens
     */
    RSAEphemeralKey(int keySize, Tpm tpm, @CheckForNull List<byte[]> tokenList)
    {
        super(tpm);
        if(tokenList == null)
        {
            tokens = new ArrayList<>(2);
            // authValue in the sensitive data section of the key, same size as the key's name hash.
            tokens.add(TpmUtils.randomBytes(tpm, SHA256.getNumBits()/8));
            // secretData in the sensitive data section of the key, same size as the key's name hash.
            tokens.add(TpmUtils.randomBytes(tpm, SHA256.getNumBits()/8));
        }
        else
        {
            if(tokenList.size() != 2)
            {
                throw new LetsConfideException("Could not reconstitute ephemeral key invalid number of tokens "+tokenList.size());
            }
            this.tokens = tokenList;
        }
        byte[] authValue = tokens.get(0);
        byte[] secretData = tokens.get(1);
        TPMS_SENSITIVE_CREATE sens = new TPMS_SENSITIVE_CREATE(authValue, secretData);
        CreatePrimaryResponse cRes = tpm.CreatePrimary(TPM_HANDLE.from(TPM_RH.NULL), sens, getPrimaryTemplate(keySize), new byte[0], new TPMS_PCR_SELECTION[0]);
        keyHandle = cRes.handle;
        keyHandle.AuthValue = authValue;
    }

    private static TPMT_PUBLIC getPrimaryTemplate(int keySize)
    {
        return new TPMT_PUBLIC(
                TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.decrypt, TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.noDA, TPMA_OBJECT.userWithAuth, TPMA_OBJECT.sensitiveDataOrigin),
                new byte[0],
                new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(), getRsaPaddingScheme(), keySize, 65537),
                new TPM2B_PUBLIC_KEY_RSA());
    }

    @Override
    public TPM_HANDLE getKeyHandle()
    {
        return keyHandle;
    }

    @Override
    public byte[] wrap(byte[] dek)
    {
        return getTpm().RSA_Encrypt(getKeyHandle(), dek, getRsaPaddingScheme(), new byte[0]);
    }

    @Override
    public byte[] unwrap(byte[] encryptedDek)
    {
        return getTpm().RSA_Decrypt(getKeyHandle(), encryptedDek, getRsaPaddingScheme(), new byte[0]);
    }

    @Override
    public List<byte[]> getTokens()
    {
        return tokens;
    }
}
