package org.letsconfide.platform.tpm;

import org.junit.Assert;
import org.junit.Test;
import tss.Tpm;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

public class TpmUtilsTest
{
    @Test
    public void testRandomBytes()
    {
        Tpm tpm = new Tpm()
        {
            final Random random = new Random();
            @Override
            public byte[] GetRandom(int bytesRequested)
            {
                byte[] result = new byte[Math.min(bytesRequested, 48)];
                random.nextBytes(result);
                return result;
            }
        };
        byte[] result = TpmUtils.randomBytes(tpm, 512);
        byte[] addedBytes = Arrays.copyOfRange(result, 48, 512);
        Assert.assertNotEquals(BigInteger.ZERO, new BigInteger(1, addedBytes));

    }

}
