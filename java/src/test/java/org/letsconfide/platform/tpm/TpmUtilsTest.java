package org.letsconfide.platform.tpm;

import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;

public class TpmUtilsTest
{
    @Test
    public void testRandomBytes()
    {
        byte[] result = TpmUtils.randomBytes(new RngOnlyTpm(), 512);
        byte[] addedBytes = Arrays.copyOfRange(result, 48, 512);
        Assert.assertNotEquals(BigInteger.ZERO, new BigInteger(1, addedBytes));

    }

}
