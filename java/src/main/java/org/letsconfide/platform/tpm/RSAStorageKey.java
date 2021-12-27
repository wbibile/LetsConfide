package org.letsconfide.platform.tpm;

import org.letsconfide.LetsConfideException;
import org.letsconfide.config.ConfigHeaders;
import tss.Tpm;
import tss.tpm.*;

import java.util.ArrayList;
import java.util.List;

import static org.letsconfide.platform.tpm.TpmUtils.getRsaPaddingScheme;

/**
 * Represents an RSA storage key on the TPM, used for key encryption.
 * The constructed storage key is attached to a primary key in the storage hierarchy of the TPM.
 * RSA padding used is OAEP.
 */
public class RSAStorageKey extends TPMKey implements TpmKeyEncryptionKey
{

    private final TPM_HANDLE keyHandle;
    private final ConfigHeaders headers;
    private final List<byte[]> keyTokens;

    /**
     * Instantiates a {@link RSAStorageKey} by reconstituting a previously generated key.
     * @param keyTokens Tokens from the previously generated key
     * @param primaryKey The primary key
     * @param headers Config headers
     */
    public RSAStorageKey(List<byte[]> keyTokens, TPMKey primaryKey, ConfigHeaders headers)
    {
        super(primaryKey.getTpm());
        this.headers = headers;
        this.keyHandle = TpmUtils.loadStorageKey(keyTokens.get(0), keyTokens.get(1), primaryKey);
        this.keyTokens = keyTokens;
    }

    /**
     * Instantiates a {@link RSAStorageKey} by generating a new key
     * @param primaryKey The primary key
     * @param headers Config headers
     */
    RSAStorageKey(TPMKey primaryKey, ConfigHeaders headers)
    {
        super(primaryKey.getTpm());
        this.headers = headers;
        CreateResponse resp = createStorageKey(primaryKey, headers);
        byte[] privateBytes = resp.outPrivate.toBytes();
        byte[] publicBytes = resp.outPublic.toBytes();
        keyTokens = new ArrayList<>(2);
        keyTokens.add(privateBytes);
        keyTokens.add(publicBytes);
        keyHandle = TpmUtils.loadStorageKey(privateBytes, publicBytes, primaryKey);
    }

    private static CreateResponse createStorageKey(TPMKey primaryKey, ConfigHeaders headers)
    {

        ConfigHeaders.CipherType storageKeyType = headers.getStorageKeyType();
        if(!storageKeyType.isRsa())
        {
            throw new LetsConfideException("Expected RSA storage key");
        }
        Tpm tpm = primaryKey.getTpm();
        try(WithPcrPolicySession withSession = new WithPcrPolicySession(tpm, headers))
        {
            withSession.initPcrPolicy();
            return primaryKey.getTpm().Create(primaryKey.getKeyHandle(),
                    /*Can't have any sensitive values because HMAC auth is not supported by the TSS*/
                    new TPMS_SENSITIVE_CREATE(new byte[0], new byte[0]), getRsaTemplate(tpm, storageKeyType.getNumBits(),withSession.getSessionHandle()), new byte[0], new TPMS_PCR_SELECTION[0]);
        }

    }

    private static TPMT_PUBLIC getRsaTemplate(Tpm tpm, int keySize, TPM_HANDLE session)
    {
        byte[] policyDigest = tpm.PolicyGetDigest(session);
        return new TPMT_PUBLIC(
                TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.decrypt, TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.noDA, TPMA_OBJECT.sensitiveDataOrigin),
                policyDigest,
                new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(), getRsaPaddingScheme(), keySize, 65537),
                new TPM2B_PUBLIC_KEY_RSA());
    }

    @Override
    public byte[] wrap(byte[] dek)
    {
        return getTpm().RSA_Encrypt(getKeyHandle(), dek, getRsaPaddingScheme(), new byte[0]);
    }

    @Override
    public byte[] unwrap(byte[] encryptedDek)
    {
        try(WithPcrPolicySession withSession = new WithPcrPolicySession(getTpm(), headers))
        {
            withSession.initPcrPolicy();
            return getTpm()._withSession(withSession.getSessionHandle()).RSA_Decrypt(getKeyHandle(), encryptedDek, getRsaPaddingScheme(), new byte[0]);
        }
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
}
