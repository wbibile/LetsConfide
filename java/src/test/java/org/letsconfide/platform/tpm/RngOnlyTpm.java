package org.letsconfide.platform.tpm;

import tss.Tpm;

import java.util.Random;

/**
 * A TPM used by tests that is only capable of generating random numbers.
 */
public class RngOnlyTpm extends Tpm
{
    static final Random RANDOM = new Random();

    @Override
    public byte[] GetRandom(int bytesRequested)
    {
        byte[] result = new byte[Math.min(bytesRequested, 48)];
        RANDOM.nextBytes(result);
        return result;
    }
}
