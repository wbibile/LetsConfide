package org.letsconfide.platform.tpm;

import org.letsconfide.LetsConfideException;
import org.letsconfide.Utils;
import tss.Tpm;

import java.util.ArrayList;
import java.util.List;

/**
 * Responsible for handling DEK (Data Encryption Key) wrap and unwrap operations using a TPM based AES KEK (Key Encryption Key).
 * This class centralizes the management of the IV (Initialization Vector) used the block cipher mode of operation.
 */
abstract class AESWrapUnwrapHandler
{
    private final Tpm tpm;

    /**
     * @param tpm The TPM
     */
    AESWrapUnwrapHandler(Tpm tpm)
    {
        this.tpm = tpm;
    }

    /**
     * Wraps a DEK.
     * @param dek DEK to be wrapped
     * @return Wrapped DEK
     */
    byte[] wrap(byte[] dek)
    {
        byte[] iv = TpmUtils.randomBytes(tpm, 16);
        List<byte[]> result = new ArrayList<>(2);
        result.add(iv);
        result.add(doWrap(iv, dek));
        return Utils.createSizedByteArray(result);
    }

    /**
     * Wraps the DEK using the device.
     * @param iv  The IV
     * @param dek The DEK
     * @return Wrapped DEK
     */
    abstract byte[] doWrap(byte[] iv, byte[] dek);

    /**
     * Unwraps a wrapped DEK.
     * @param wrappedDek DEK to be unwrapped
     * @return Unwrapped DEK
     */
    byte[] unwrap(byte[] wrappedDek)
    {
        List<byte[]> parts = Utils.splitSizedByteArray(wrappedDek);
        if (parts.size() != 2)
        {
            throw new LetsConfideException("Encrypted key format is invalid");
        }
        return doUnwrap(parts.get(0), parts.get(1));
    }

    /**
     * Unwraps the DEK using the device.
     * @param iv  The IV
     * @param wrappedDek The DEK
     * @return Unwrapped DEK
     */
    abstract byte[] doUnwrap(byte[] iv, byte[] wrappedDek);

}
