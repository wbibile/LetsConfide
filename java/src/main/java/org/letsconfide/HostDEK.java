package org.letsconfide;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.letsconfide.platform.SecurityDevice;

import java.util.function.Function;

import static org.letsconfide.Utils.hashHsa256;
import static org.letsconfide.Utils.isZero;

/**
 * Represents a symmetric data encryption key (DEK) on the host (meaning key/data are applied to
 * the cipher on the host CPU). The key uses an AES256 cipher operating in GCM mode. <BR>
 * Unless the key is being used, the key is usually encrypted using a key-encryption-key (KEK)
 * on the device(TPM).<BR>
 * An AES data encryption key and a seed is generated securely using the device. <BR>
 * The seed is 512 bits long, it is used to generate the following information used by the (GCM)
 * mode of operation of the AES cipher.
 * <UL>
 * <LI>Initialization vector: SHA256(seed) </LI>
 * <LI>Associated text: this is equal to the seed</LI>
 * </UL>
 */
public class HostDEK
{

    // Key size in bytes (256 bit)
    public static final int KEY_SIZE = 32;
    private final byte[] encryptedKey;
    private final boolean isEphemeral;
    private final byte[] gcmAssociatedText;
    private final byte[] iv;

    /**
     * @param isEphemeral       Whether this key is an ephemeral key
     * @param encryptedKey      The encrypted key
     * @param iv                The initialization vector
     * @param gcmAssociatedText GCM associated text (additional information added to GCMs MAC)
     */
    private HostDEK(boolean isEphemeral, byte[] encryptedKey, byte[] iv, byte[] gcmAssociatedText)
    {
        this.encryptedKey = encryptedKey;
        this.isEphemeral = isEphemeral;
        this.iv = iv;
        this.gcmAssociatedText = gcmAssociatedText;
    }

    /**
     * Creates new instance and generates the associated key and seed.
     *
     * @param isEphemeral Whether this key is an ephemeral key
     * @param device The security device
     * @return A new instance
     */
    public static HostDEK generateNew(boolean isEphemeral, SecurityDevice device)
    {
        return generateNew(isEphemeral, device, device.getRandomBytes(KEY_SIZE * 2));
    }


    /**
     * Creates new instance and generates the associated key.
     *
     * @param isEphemeral Whether this key is an ephemeral key
     * @param device The security device
     * @param seed The seed to use
     * @return A new instance
     */
    public static HostDEK generateNew(boolean isEphemeral, SecurityDevice device, byte[] seed)
    {
        assert (seed.length >= KEY_SIZE * 2);
        byte[] keyBytes;
        do
        {

            // Note that the key is generated using the device, it is not derived from the seed.
            // Because it is important for the seed and the key-bytes are independent.
            keyBytes = device.getRandomBytes(KEY_SIZE);

        }
        while (isZero(keyBytes, 0, KEY_SIZE / 2));
        Function<byte[], byte[]> encFunc = isEphemeral ? device::wrapEphemeral : device::wrap;
        // this is
        HostDEK result = from(isEphemeral, encFunc.apply(keyBytes), seed);
        Utils.erase(keyBytes);
        return result;
    }

    /**
     * Reconstitutes a data encryption key from existing data.
     * @param isEphemeral Whether this key is an ephemeral key
     * @param encryptedBytes encrypted key bytes
     * @param seed the seed
     * @return A new instance
     */
    public static HostDEK from(boolean isEphemeral, byte[] encryptedBytes, byte[] seed)
    {
        // Both GCM iv and gcm associated text (used for MAC validation) are derived from the seed.
        byte[] seedHash = hashHsa256(seed);
        byte iv[] = new byte[12];// GCM mode use 12 byte IVs.
        System.arraycopy(seedHash, 0, iv, 0, iv.length);// Take the first 12 bytes of the hash
        return new HostDEK(isEphemeral, encryptedBytes, iv, /*associated text*/seed);
    }

    /**
     * @return The encrypted key
     */
    byte[] getEncryptedKey()
    {
        return encryptedKey;
    }

    /**
     * Decrypts this key using the device.
     * @param device the device
     * @return the decrypted key
     */
    private byte[] getKey(SecurityDevice device)
    {
        Function<byte[], byte[]> decFunc = isEphemeral ? device::unwrapEphemeral : device::unwrap;
        byte[] result = new byte[KEY_SIZE];
        byte[] decryptedKey = decFunc.apply(encryptedKey);
        if (decryptedKey.length != KEY_SIZE)
        {
            // TODO: appropriate message.
            throw new LetsConfideException();
        }
        System.arraycopy(decryptedKey, 0, result, 0, result.length);
        Utils.erase(decryptedKey);
        return result;
    }

    /**
     * Encrypts data using this key.
     * This method uses the device to decrypt this key, then applies the decrypted DEK to encrypt the given plain text.
     * @param device the device
     * @param plainText pain text bytes to encrypt
     * @return The cipher text
     */
    byte[] encrypt(SecurityDevice device, byte[] plainText)
    {
        try (ResolvedDek resolvedKey = new ResolvedDek(device))
        {
            return resolvedKey.encrypt(plainText);
        }
    }

    /**
     * decrypts data using this key.
     * This method uses the device to decrypt this key, then applies the decrypted DEK to decrypt the given cipher text.
     * @param device the device
     * @param cipherText cipher text to be decrypted
     * @return The plain text
     */
    byte[] decrypt(SecurityDevice device, byte[] cipherText)
    {
        try (ResolvedDek resolvedKey = new ResolvedDek(device))
        {
            return resolvedKey.decrypt(cipherText);
        }
    }

    /**
     * Creates a new {@link ResolvedDek}.
     * @param device the device
     * @return the
     */
    ResolvedDek newResolvedDek(SecurityDevice device)
    {
        return new ResolvedDek(device);
    }

    /**
     * Represents a resolved copy of the enclosing {@link HostDEK}.
     * Objects is instantiated by decrypting the encrypted key bytes.
     */
    public class ResolvedDek implements LetsConfideCloseable
    {
        // Decrypted key bytes.
        private final byte[] keyBytes;

        private ResolvedDek(SecurityDevice device)
        {
            this.keyBytes = getKey(device);
        }

        /**
         * Encrypts data using this resolved (decrypted) key.
         * @param plainText pain text bytes to encrypt
         * @return The cipher text
         */
        public byte[] encrypt(byte[] plainText)
        {
            try
            {
                return Utils.aesGsmEncryptDecrypt(false, keyBytes, iv, gcmAssociatedText, plainText);
            }
            catch (InvalidCipherTextException e)
            {
                // Don't propagate exception, may contain too much information.
                throw new LetsConfideException("Could not encrypt data: Plain text is invalid.");
            }
        }

        /**
         * Decrypts data using this key.
         * @param cipherText cipher text to be decrypted
         * @return The plain text
         */
        public byte[] decrypt(byte[] cipherText)
        {
            try
            {
                return Utils.aesGsmEncryptDecrypt(true, keyBytes, iv, gcmAssociatedText, cipherText);
            }
            catch (InvalidCipherTextException e)
            {
                // Don't propagate exception, may contain too much information.
                throw new LetsConfideException("Could not decrypt data: Invalid cipher text.");
            }
        }

        /**
         * Erases the decrypted key bytes.
         */
        @Override
        public void close()
        {
            Utils.erase(keyBytes);
        }
    }

}
