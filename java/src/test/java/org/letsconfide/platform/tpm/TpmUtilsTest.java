package org.letsconfide.platform.tpm;

import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

public class TpmUtilsTest
{
    @Test
    public void testRandomBytes()
    {
        byte[] generated = new byte[48];
        new Random().nextBytes(generated);
        byte[] result = TpmUtils.randomBytes(generated, 512);
        Assert.assertArrayEquals(generated, Arrays.copyOf(result, 48));

        byte[] addedBytes = Arrays.copyOfRange(result, 48, 512);
        Assert.assertNotEquals(BigInteger.ZERO, new BigInteger(1, addedBytes));

    }

}
