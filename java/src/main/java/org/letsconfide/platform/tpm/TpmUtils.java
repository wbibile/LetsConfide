package org.letsconfide.platform.tpm;

import org.letsconfide.LetsConfideException;
import org.letsconfide.config.ConfigHeaders;
import tss.Tpm;
import tss.tpm.*;

import java.nio.ByteBuffer;

/**
 * TPM related utilities.
 */
class TpmUtils
{
    /**
     * Maximum PCR flag value.
     */
     private static final int MAX_PCR_VALUE = 0xFFFFFF;

    /**
     * Generates random bytes using the TPM.
     * @param tpm The TPM
     * @param size Number of bytes to generate
     * @return the generated bytes.
     */
    static byte[] randomBytes(Tpm tpm, int size)
    {
        byte[] result = new byte[size];
        int i=0;
        do
        {
            byte[] generated = tpm.GetRandom(size-i);
            System.arraycopy(generated, 0, result, i, generated.length);
            i+=generated.length;
        } while(i < size);
        return result;
    }

    /**
     * @return RSA padding scheme used by the TPM
     */
    static TPMU_ASYM_SCHEME getRsaPaddingScheme()
    {
        // All TPM based RSA key encryption keys use OAEP padding (not suitable for RSA primary keys).
        return new TPMS_SCHEME_OAEP(TPM_ALG_ID.SHA256);
    }

    /**
     * Compute the PCR selection using the given headers.
     * @param headers config headers
     * @return PCR selection
     */
    static TPMS_PCR_SELECTION[] getPcrSelection(ConfigHeaders headers)
    {
        TPM_ALG_ID algId;
        switch (headers.getPcrHash())
        {
            case SHA256:
                algId = TPM_ALG_ID.SHA256;
                break;
            case SHA1:
                algId = TPM_ALG_ID.SHA1;
                break;
            default:
                throw new LetsConfideException("Algorithm "+headers.getPcrHash()+" +not supported.");
        }
        TPMS_PCR_SELECTION pcr0Sha256 = new TPMS_PCR_SELECTION(algId, toPCRBytes(headers.getPcrSelection()));
        return new TPMS_PCR_SELECTION[]{pcr0Sha256};
    }

    /**
     * Converts the PCR selection header value to PCR bytes.
     * @param pcrSelection the PCR selection
     * @return PCR bytes
     */
    private static byte[] toPCRBytes(int pcrSelection)
    {
        if(pcrSelection > MAX_PCR_VALUE)
        {
            throw new LetsConfideException("PCR selection is too large.");
        }
        if(pcrSelection <= 0)
        {
            throw new LetsConfideException("PCR selection can't be negative or zero.");
        }
        byte[] bytes = ByteBuffer.allocate(4).putInt(pcrSelection).array();
        // PCR selection is 24 bits (determined experimentally).
        byte[] result = new byte[3];
        System.arraycopy(bytes, 1, result,0, result.length);
        return result;
    }

    /**
     * Helper method for loading a storage key.
     * @param privateBytes Private bytes associated with the key
     * @param publicBytes Public bytes associated with the key
     * @param primary The primary key
     * @return Handle to the loaded storage key
     */
    static TPM_HANDLE loadStorageKey(byte[] privateBytes, byte[] publicBytes, TPMKey primary)
    {
        return primary.getTpm().Load(primary.getKeyHandle(), TPM2B_PRIVATE.fromBytes(privateBytes), TPMT_PUBLIC.fromBytes(publicBytes));
    }

}
