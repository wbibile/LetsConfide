package org.letsconfide.platform.tpm;

import org.letsconfide.LetsConfideException;
import org.letsconfide.Utils;
import org.letsconfide.config.ConfigHeaders;
import tss.Tpm;
import tss.tpm.*;

import java.util.ArrayList;
import java.util.List;

import static org.letsconfide.platform.tpm.TpmUtils.loadStorageKey;

/**
 * Represents an AES storage key on the TPM, used for key encryption.
 * The constructed storage key is attached to a primary key in the storage hierarchy of the TPM.
 * The AES mode of operation is CFB (Cipher Feedback).
 */
public class AESStorageKey extends TPMKey implements TpmKeyEncryptionKey
{
    private final TPM_HANDLE keyHandle;

    private final List<byte[]> keyTokens;
    private final ConfigHeaders headers;

    /**
     * Instantiates a {@link AESStorageKey} by reconstituting a previously generated key.
     * @param keyTokens Tokens from the previously generated key
     * @param primaryKey The primary key
     * @param headers Config headers
     */
    public AESStorageKey(List<byte[]> keyTokens, TPMKey primaryKey, ConfigHeaders headers)
    {
        super(primaryKey.getTpm());
        this.headers = headers;
        this.keyHandle = loadStorageKey(keyTokens.get(0), keyTokens.get(1), primaryKey);
        this.keyTokens = keyTokens;
    }

    /**
     * Instantiates a {@link AESStorageKey} by generating a new key
     * @param primaryKey The primary key
     * @param headers Config headers
     */
    public AESStorageKey(TPMKey primaryKey, ConfigHeaders headers)
    {
        super(primaryKey.getTpm());
        this.headers = headers;
        CreateResponse resp = createStorageKey(primaryKey, headers);
        byte[] privateBytes = resp.outPrivate.toBytes();
        byte[] publicBytes = resp.outPublic.toBytes();
        keyTokens = new ArrayList<>(2);
        keyTokens.add(privateBytes);
        keyTokens.add(publicBytes);
        keyHandle = loadStorageKey(privateBytes, publicBytes, primaryKey);
    }

    private static CreateResponse createStorageKey(TPMKey primaryKey, ConfigHeaders headers)
    {

        ConfigHeaders.CipherType storageKeyType = headers.getStorageKeyType();
        if(!storageKeyType.isAes())
        {
            throw new LetsConfideException("Expected AES storage key");
        }
        Tpm tpm = primaryKey.getTpm();
        TPM_HANDLE primaryKeyHandle = primaryKey.getKeyHandle();

        try(WithPcrPolicySession withSession = new WithPcrPolicySession(tpm, headers))
        {
            withSession.initPcrPolicy();
            TPMT_PUBLIC aesTemplate = createAesTemplate(tpm, storageKeyType.getNumBits(), withSession.getSessionHandle());
            return tpm.Create(primaryKeyHandle,
                    /*Can't have any sensitive values because HMAC auth is not supported by the TSS*/
                    new TPMS_SENSITIVE_CREATE(new byte[0], new byte[0]), aesTemplate, new byte[0], new TPMS_PCR_SELECTION[0]);
        }

    }

    private static TPMT_PUBLIC createAesTemplate(Tpm tpm, int keySize, TPM_HANDLE session)
    {
        byte[] policyDigest = tpm.PolicyGetDigest(session);
        return new TPMT_PUBLIC(
                TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.encrypt, TPMA_OBJECT.decrypt, TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.sensitiveDataOrigin),
                policyDigest,
                new TPMS_SYMCIPHER_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, keySize, TPM_ALG_ID.CFB)),
                new TPM2B_DIGEST_SYMCIPHER());
    }

    @Override
    public TPM_HANDLE getKeyHandle()
    {
        return keyHandle;
    }

    @Override
    public List<byte[]> getTokens()
    {
        return keyTokens;
    }

    @Override
    public byte[] wrap(byte[] dek)
    {
        byte[] iv = TpmUtils.randomBytes(getTpm(), 16);
        List<byte[]> result = new ArrayList<>(2);
        result.add(iv);
        try(WithPcrPolicySession withSession = new WithPcrPolicySession(getTpm(), headers))
        {
            withSession.initPcrPolicy();
            // No special key wrapping algorithm is used as we are using randomly generated IV.
            byte[] encKey = getTpm()._withSession(withSession.getSessionHandle()).EncryptDecrypt(keyHandle, (byte) 0, TPM_ALG_ID.CFB, iv, dek).outData;
            result.add(encKey);

        }
        return Utils.createSizedByteArray(result);
    }

    @Override
    public byte[] unwrap(byte[] encryptedDek)
    {
        List<byte[]> parts = Utils.splitSizedByteArray(encryptedDek);
        if(parts.size() != 2)
        {
            throw new LetsConfideException("Encrypted key format is invalid");
        }
        byte[] iv = parts.get(0);
        byte[] encKey = parts.get(1);
        try(WithPcrPolicySession withSession = new WithPcrPolicySession(getTpm(), headers))
        {
            withSession.initPcrPolicy();
            return getTpm()._withSession(withSession.getSessionHandle()).EncryptDecrypt(keyHandle, (byte) 1, TPM_ALG_ID.CFB, iv, encKey).outData;
        }
    }
    
}
