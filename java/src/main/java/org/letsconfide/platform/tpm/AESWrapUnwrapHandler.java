package org.letsconfide.platform.tpm;

import org.letsconfide.LetsConfideException;
import org.letsconfide.Utils;
import tss.Tpm;

import java.util.ArrayList;
import java.util.List;

import static org.letsconfide.HostDEK.KEY_SIZE;

/**
 * Responsible for handling DEK (Data Encryption Key) wrap and unwrap operations using a TPM based AES KEK (Key Encryption Key).
 * This class centralizes the management of the IV (Initialization Vector) used the block cipher mode of operation and management of additional padding.
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
        if(dek.length != KEY_SIZE)
        {
            throw new LetsConfideException("Unexpected AES256 key size");
        }
        byte[] padding = TpmUtils.randomBytes(tpm, KEY_SIZE);
        byte[] dekWithPadding = new byte[KEY_SIZE*2];
        System.arraycopy(dek, 0, dekWithPadding, 0, KEY_SIZE);
        System.arraycopy(padding, 0, dekWithPadding, KEY_SIZE, KEY_SIZE);

        // Generate a non zero IV.
        byte[] iv;
        do
        {
            iv = TpmUtils.randomBytes(tpm, 16);
        }
        while(Utils.isZero(iv, 0, iv.length));
        List<byte[]> result = new ArrayList<>(2);
        result.add(iv);
        result.add(doWrap(iv, dekWithPadding));
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
    byte[] unwrap(byte[] wrappedDek) throws LetsConfideException
    {
        List<byte[]> parts;
        try
        {
            parts = Utils.splitSizedByteArray(wrappedDek);
        }
        catch (LetsConfideException e)
        {
            LetsConfideException e2 = invalidKeyFormatException();
            e2.initCause(e);
            throw e2;
        }
        if (parts.size() != 2)
        {
            throw invalidKeyFormatException();
        }
        byte[] keyWithPadding = doUnwrap(parts.get(0), parts.get(1));
        if(keyWithPadding.length != KEY_SIZE*2)
        {
            throw new LetsConfideException("Invalid encrypted key length");
        }
        byte[] result = new byte[KEY_SIZE];
        System.arraycopy(keyWithPadding, 0, result,0, KEY_SIZE);
        Utils.erase(keyWithPadding);
        return result;
    }

    private static LetsConfideException invalidKeyFormatException()
    {
        return new LetsConfideException("Encrypted key format is invalid");
    }


    /**
     * Unwraps the DEK using the device.
     * @param iv  The IV
     * @param wrappedDek The DEK
     * @return Unwrapped DEK
     */
    abstract byte[] doUnwrap(byte[] iv, byte[] wrappedDek);

}
