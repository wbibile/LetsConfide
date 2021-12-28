package org.letsconfide.platform.tpm;

import org.letsconfide.LetsConfideException;
import org.letsconfide.config.ConfigHeaders;
import org.letsconfide.platform.SecurityDevice;
import tss.Tpm;

import javax.annotation.CheckForNull;
import java.io.IOException;
import java.util.List;

/**
 * Security device based on the TPM.
 * Note that, all operations on the TPM are synchronized and are time-consuming
 * (in the order of hundreds of milliseconds), this is because the TPMs are typically resource constrained devices.
 */
class TPMDevice implements SecurityDevice
{
    private final Tpm tpm;
    private final TPMKey primaryKey;
    private final TpmKeyEncryptionKey storageKey;
    private final TpmKeyEncryptionKey ephemeralKey;

    // Context for synchronizing access to the TPM.
    private final Object tpmSync;

    /**
     * @param tpm The TPM
     * @param headers Config headers
     * @param deviceTokens device tokens used for reconstituting previous persistent state
     * @param ephemeralTokens device tokens used for reconstituting previous ephemeral state
     */
    TPMDevice(Tpm tpm, Object tpmSync, ConfigHeaders headers, List<byte[]> deviceTokens, List<byte[]> ephemeralTokens)
    {
        this.tpm = tpm;
        this.tpmSync = tpmSync;
        // Disallow concurrent operations on the TPM
        synchronized(this.tpmSync)
        {
            primaryKey = createPrimary(tpm, headers);
            storageKey = createStorageKey(primaryKey, headers, deviceTokens);
            ephemeralKey = createEphemeralKey(tpm,headers, ephemeralTokens);
        }
    }

    private static TPMKey createPrimary(Tpm tpm, ConfigHeaders headers)
    {
        ConfigHeaders.CipherType type = headers.getPrimaryKeyType();
        if(type.isRsa())
        {
            return new RSAPrimaryKey(tpm, type.getNumBits());
        }
        else
        {
            if(!type.isAes())
            {
                throw new LetsConfideException("Primary key type not supported");
            }
            return new AESPrimaryKey(type.getNumBits(), tpm);
        }
    }

    private static TpmKeyEncryptionKey createStorageKey(TPMKey primaryKey, ConfigHeaders headers, @CheckForNull List<byte[]> deviceTokens)
    {
        ConfigHeaders.CipherType type = headers.getStorageKeyType();
        if(type.isRsa())
        {
            return deviceTokens != null? new RSAStorageKey(deviceTokens, primaryKey, headers): new RSAStorageKey(primaryKey, headers);
        }

        else
        {
            if(!type.isAes())
            {
                throw new LetsConfideException("Storage key type not supported");
            }
            return deviceTokens != null ? new AESStorageKey(deviceTokens, primaryKey, headers) : new AESStorageKey(primaryKey, headers);
        }
    }

    private static TpmKeyEncryptionKey createEphemeralKey(Tpm tpm, ConfigHeaders headers, @CheckForNull List<byte[]> ephemeralTokens)
    {
        ConfigHeaders.CipherType type = headers.getEphemeralKeyType();
        if(type.isRsa())
        {
            return new RSAEphemeralKey(type.getNumBits(), tpm, ephemeralTokens);
        }
        else
        {
            if(!type.isAes())
            {
                throw new LetsConfideException("Storage key type not supported");
            }
            return  new AesEphemeralKey(type.getNumBits(), tpm, ephemeralTokens);
        }
    }

    /**
     * @return List of tokens that can be used for reconstituting previous persistent state
     */
    List<byte[]> getDeviceTokens()
    {
        return storageKey.getTokens();
    }

    /**
     * @return List of tokens that can be used for reconstituting previous ephemeral state
     */
    List<byte[]> getEphemeralTokens()
    {
        return ephemeralKey.getTokens();
    }

    @Override
    public byte[] wrap(byte[] dek)
    {
        // Disallow concurrent operations on the TPM
        synchronized(tpmSync)
        {
            return storageKey.wrap(dek);
        }
    }

    @Override
    public byte[] unwrap(byte[] encryptedDek)
    {
        // Disallow concurrent operations on the TPM
        synchronized(tpmSync)
        {
            return storageKey.unwrap(encryptedDek);
        }
    }

    @Override
    public byte[] wrapEphemeral(byte[] dek)
    {
        // Disallow concurrent operations on the TPM
        synchronized(tpmSync)
        {
            return ephemeralKey.wrap(dek);
        }
    }

    @Override
    public byte[] unwrapEphemeral(byte[] encryptedDek)
    {
        // Disallow concurrent operations on the TPM
        synchronized(tpmSync)
        {
            return ephemeralKey.unwrap(encryptedDek);
        }
    }

    @Override
    public byte[] getRandomBytes(int size)
    {
        // Disallow concurrent operations on the TPM
        synchronized(tpmSync)
        {
            return TpmUtils.randomBytes(tpm, size);
        }
    }

    @Override
    public void close() throws LetsConfideException
    {
        // Disallow concurrent operations on the TPM
        synchronized(tpmSync)
        {
            tpm.FlushContext(storageKey.getKeyHandle());
            tpm.FlushContext(primaryKey.getKeyHandle());
            tpm.FlushContext(ephemeralKey.getKeyHandle());
            try
            {
                tpm.close();
            }
            catch (IOException e)
            {
                throw new LetsConfideException("Error closing the TPM connection", e);
            }
        }
    }

}
