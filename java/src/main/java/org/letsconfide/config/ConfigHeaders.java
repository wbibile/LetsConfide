package org.letsconfide.config;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Represents configurations headers as specified in the input YAML file.
 */
public class ConfigHeaders
{

    private static final Pattern AES_PATTERN = Pattern.compile("AES\\d{3}");
    private static final Pattern RSA_PATTERN = Pattern.compile("RSA\\d{4}");

    /**
     * Represents types of ciphers being used.
     */
    public enum CipherType
    {
        AES128(128),
        AES256(256),
        /*
         * AES192 is disabled in the TPM reference implementation
         * See TpmProfile.h in
         * <https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part4_SuppRoutines_code_pub.pdf>
         *
         * #define AES_192                     (ALG_AES && NO)
         */
        //AES192(192),
        RSA1024(1024),
        RSA2048(2048);

        private final int numBits;

        CipherType(int numBits)
        {
            this.numBits = numBits;
        }

        /**
         * @return Number of bits used to define the key
         */
        public int getNumBits()
        {
            return numBits;
        }

        /**
         * @return true if this key is an RSA key
         */
        public boolean isRsa()
        {
            return RSA_PATTERN.matcher(name()).matches();
        }

        /**
         * @return true if this key is an AES key
         */
        public boolean isAes()
        {
            return AES_PATTERN.matcher(name()).matches();
        }
    }

    /**
     * Represents types of hashing algorithms being used.
     */
    public enum HashType
    {
        SHA256(256),
        SHA1(160);
        private final int numBits;
        HashType(int numBits)
        {
            this.numBits = numBits;
        }

        public int getNumBits()
        {
            return numBits;
        }
    }

    /**
     * Default config header values.
     */
    public static final ConfigHeaders DEFAULT = new ConfigHeaders(CipherType.AES256, CipherType.AES256, CipherType.AES256, /*selects PCR0 on the TPM*/0x10000, HashType.SHA256);

    private final CipherType primaryKeyType;
    private final CipherType storageKeyType;
    private final CipherType ephemeralKeyType;
    // Note that PCR selection only uses the first 24 bits.
    private final int pcrSelection;
    private final HashType pcrHash;

    /**
     * @param primaryKeyType The primary key type
     * @param storageKeyType The storage key type
     * @param ephemeralKeyType The null key type
     * @param pcrSelection The PCR selection
     * @param pcrHash The PCR hash
     */
    public ConfigHeaders(CipherType primaryKeyType, CipherType storageKeyType, CipherType ephemeralKeyType, int pcrSelection, HashType pcrHash)
    {
        this.primaryKeyType = primaryKeyType;
        this.storageKeyType = storageKeyType;
        this.pcrSelection = pcrSelection;
        this.pcrHash = pcrHash;
        this.ephemeralKeyType = ephemeralKeyType;
    }

    /**
     * @return The primary key type
     */
    public CipherType getPrimaryKeyType()
    {
        return primaryKeyType;
    }

    /**
     * @return The storage key type
     */
    public CipherType getStorageKeyType()
    {
        return storageKeyType;
    }

    /**
     * @return The PCR selection
     */
    public int getPcrSelection()
    {
        return pcrSelection;
    }

    /**
     * @return The PCR hash
     */
    public HashType getPcrHash()
    {
        return pcrHash;
    }

    /**
     * @return The ephemeral key type
     */
    public CipherType getEphemeralKeyType()
    {
        return ephemeralKeyType;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }
        ConfigHeaders headers = (ConfigHeaders) o;
        return pcrSelection == headers.pcrSelection &&
                primaryKeyType == headers.primaryKeyType &&
                storageKeyType == headers.storageKeyType &&
                pcrHash == headers.pcrHash;
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(primaryKeyType, storageKeyType, pcrSelection, pcrHash);
    }

}
