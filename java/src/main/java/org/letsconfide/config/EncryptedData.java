package org.letsconfide.config;

import java.util.List;

/**
 * Represents encrypted data specified in the input YAML file.
 */
public class EncryptedData
{
    private final byte[] seed;
    private final byte[] encKey;
    private final byte[] cipherData;
    private final List<byte[]> deviceTokens;

    /**
     * @param seed The seed
     * @param encryptedKey An encrypted DEK
     * @param cipherData Data encrypted using the DEK
     * @param deviceTokens Device tokens
     */
    public EncryptedData(byte[] seed, byte[] encryptedKey, byte[] cipherData, List<byte[]> deviceTokens)
    {
        this.seed = seed;
        this.encKey = encryptedKey;
        this.cipherData = cipherData;
        this.deviceTokens = deviceTokens;
    }

    /**
     * Gets the seed necessary for reconstituting a non-ephemeral {@link org.letsconfide.HostDEK}.
     * @return The seed
     */
    public byte[] getSeed()
    {
        return seed;
    }

    /**
     * Gets the encrypted key, which would eventually be wrapped by a non-ephemeral  {@link org.letsconfide.HostDEK}.
     * @return The encrypted key
     */
    public byte[] getEncKey()
    {
        return encKey;
    }

    /**
     * Encrypted form of the originally supplied Map data.
     * @return encrypted data
     */
    public byte[] getCipherData()
    {
        return cipherData;
    }

    /**
     * Gets the device tokens. These tokens are used to reconstitute device keys.
     * For a TPM device this consists of the private and public portions of a storage key.
     * @return The device token
     */
    public List<byte[]> getDeviceTokens()
    {
        return deviceTokens;
    }
}
