package org.letsconfide.platform.tpm;

import org.junit.Assert;
import org.junit.Test;
import org.letsconfide.LetsConfideException;
import org.letsconfide.Utils;

import java.util.Arrays;
import java.util.List;

public class AESWrapUnwrapHandlerTest
{

    /**
     * Test basic wrap unwrap behaviour.
     */
    @Test
    public void testWrapUnwrap()
    {
        byte[] aesKey = new byte[32];
        RngOnlyTpm.RANDOM.nextBytes(aesKey);

        NoEncryptAESWrapUnwrapHandler handler = new NoEncryptAESWrapUnwrapHandler();
        byte[] wrappedKey = handler.wrap(aesKey);
        // Split the IV and encryptedKey
        List<byte[]> parts = Utils.splitSizedByteArray(wrappedKey);
        Assert.assertEquals(2, parts.size());

        // Check the IV
        byte[] iv = parts.get(0);
        Assert.assertEquals(16, iv.length);
        Assert.assertFalse(Utils.isZero(iv, 0, iv.length));

        // Checking the encrypted key (which is not encrypted under the fake implementation).
        byte[] encryptedKey = parts.get(1);
        Assert.assertEquals(64, encryptedKey.length);
        // Make sure that the DEK  is prepended.
        Assert.assertArrayEquals(aesKey, Arrays.copyOfRange(encryptedKey, 32,64));

        byte[] unwrappedKey = handler.unwrap(wrappedKey);
        Assert.assertArrayEquals(aesKey, unwrappedKey);
    }

    /**
     * Test trying to wrap a key of invalid length.
     */
    @Test
    public void testWrapKeyWithInvalidLength()
    {
        byte[] aesKey = new byte[31];
        RngOnlyTpm.RANDOM.nextBytes(aesKey);
        try
        {
            byte[] wrappedKey = new NoEncryptAESWrapUnwrapHandler().wrap(aesKey);
            Assert.fail("Generated wrapped key with length "+wrappedKey.length);
        }
        catch (LetsConfideException e)
        {
            Assert.assertEquals("Unexpected AES256 key size", e.getMessage());
        }
    }

    /**
     * Trying to unwrap invalid bytes. The sized byte array is malformed.
     */
    @Test
    public void testUnwrapInvalidSizedData()
    {
        byte[] result = new byte[32];
        RngOnlyTpm.RANDOM.nextBytes(result);
        int size = result.length+1;
        result[1] = (byte)(size & 0xFF);
        result[0] = (byte)(0);

        try
        {
            byte[] unwrappedKey = new NoEncryptAESWrapUnwrapHandler().unwrap(result);
            Assert.fail("Generated unwrapped key with length "+unwrappedKey.length);
        }
        catch (LetsConfideException e)
        {
            Assert.assertEquals("Encrypted key format is invalid", e.getMessage());
            Assert.assertEquals("Invalid sized byte array, byte segment size 33 at index 2 is too large", e.getCause().getMessage());
        }
    }

    /**
     * Trying to unwrap invalid bytes. The sized byte array has only one element (expects two).
     */
    @Test
    public void testUnwrapInvalidPartCountOne()
    {
        byte[] result = new byte[32];
        RngOnlyTpm.RANDOM.nextBytes(result);
        assertInvalidPartCount(result);
    }

    /**
     * Trying to unwrap invalid bytes. The sized byte array has three elements (expects two).
     */
    @Test
    public void testUnwrapInvalidPartCountThree()
    {
        byte[] result = new byte[32];
        byte[] iv1 = new byte[16];
        byte[] iv2 = new byte[16];
        RngOnlyTpm.RANDOM.nextBytes(result);
        RngOnlyTpm.RANDOM.nextBytes(iv1);
        RngOnlyTpm.RANDOM.nextBytes(iv2);
        assertInvalidPartCount(result, iv1, iv2);
    }

    private static void assertInvalidPartCount(byte[]... parts)
    {
        byte[] sizedArray = Utils.createSizedByteArray(Arrays.asList(parts));
        try
        {
            byte[] unwrappedKey = new NoEncryptAESWrapUnwrapHandler().unwrap(sizedArray);
            Assert.fail("Generated unwrapped key with length "+unwrappedKey.length);
        }
        catch (LetsConfideException e)
        {
            Assert.assertEquals("Encrypted key format is invalid", e.getMessage());
        }
    }

    private static class NoEncryptAESWrapUnwrapHandler extends AESWrapUnwrapHandler
    {

        NoEncryptAESWrapUnwrapHandler()
        {
            super(new RngOnlyTpm());
        }

        @Override
        byte[] doWrap(byte[] iv, byte[] dek)
        {
            return dek;
        }

        @Override
        byte[] doUnwrap(byte[] iv, byte[] wrappedDek)
        {
            return wrappedDek;
        }
    }
}
