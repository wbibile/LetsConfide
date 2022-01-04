package org.letsconfide.platform;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.letsconfide.LetsConfideException;
import org.letsconfide.Utils;
import org.letsconfide.config.ConfigHeaders;

import java.nio.charset.StandardCharsets;
import java.util.*;

public class FakeDeviceFactory implements DeviceFactory
{

    @Override
    public SecurityDevice newDevice(ConfigHeaders headers, List<byte[]> deviceTokens)
    {
        return new FakeSecurityDevice(deviceTokens);
    }

    @Override
    public Map.Entry<SecurityDevice, List<byte[]>> newDevice(ConfigHeaders headers)
    {
        FakeSecurityDevice result = new FakeSecurityDevice();
        return new AbstractMap.SimpleEntry<>(result, result.deviceTokens);
    }

    private static class FakeSecurityDevice implements SecurityDevice
    {
        // Note fixed initialization vectors are not secure but this only used for testing.
        private static final byte[] TEST_IV = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".getBytes(StandardCharsets.UTF_8);
        private final byte[] aes256Key;
        private final Random random = new Random();
        final List<byte[]> deviceTokens;
        private FakeSecurityDevice()
        {
            deviceTokens= Arrays.asList(generateRandomBytes(128), generateRandomBytes(128));
            aes256Key = makeAesKey(deviceTokens);
        }

        private FakeSecurityDevice(List<byte[]> deviceTokens)
        {
            this.deviceTokens = deviceTokens;
            aes256Key = makeAesKey(deviceTokens);
        }

        private static byte[] makeAesKey(List<byte[]> deviceTokens)
        {
            assert deviceTokens.size() == 2;
            byte[] tokens0 = deviceTokens.get(0);
            byte[] tokens1 = deviceTokens.get(1);

            assert tokens0.length == 128;
            assert tokens1.length == 128;
            HMac mac = new HMac(new SHA256Digest());
            mac.init(new KeyParameter(tokens0));
            mac.update(tokens1, 0, tokens1.length);
            byte[] result = new byte[32];
            mac.doFinal(result, 0);
            return result;
        }

        @Override
        public byte[] wrap(byte[] dek)
        {
            try
            {
                return Utils.aesGsmEncryptDecrypt(false, aes256Key,TEST_IV, new byte[0], dek);
            }
            catch (InvalidCipherTextException e)
            {
                throw new LetsConfideException(e);
            }
        }

        @Override
        public byte[] unwrap(byte[] encryptedDek)
        {
            try
            {
                return Utils.aesGsmEncryptDecrypt(true, aes256Key, TEST_IV, new byte[0], encryptedDek);
            }
            catch (InvalidCipherTextException e)
            {
                throw new LetsConfideException(e);
            }
        }

        @Override
        public byte[] wrapEphemeral(byte[] dek)
        {
            return cloneBytes(dek);
        }

        @Override
        public byte[] unwrapEphemeral(byte[] encryptedDek)
        {
            return cloneBytes(encryptedDek);
        }

        @Override
        public byte[] getRandomBytes(int size)
        {
            return generateRandomBytes(size);
        }

        private byte[] generateRandomBytes(int size)
        {
            byte[] result = new byte[size];
            random.nextBytes(result);
            return result;
        }

        private static byte[] cloneBytes(byte[] source)
        {
            byte[] result = new byte[source.length];
            System.arraycopy(source, 0, result, 0, source.length);
            return result;
        }

        @Override
        public void close() throws LetsConfideException
        {
            //
        }
    }
}
