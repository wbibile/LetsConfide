package org.letsconfide;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.letsconfide.config.ConfigHeaders;
import org.letsconfide.config.EncryptedData;
import org.letsconfide.platform.DeviceFactory;
import org.letsconfide.platform.SecurityDevice;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.letsconfide.HostDEK.SEED_SIZE;


/**
 * A facade for accessing services provided by LetsConfide.
 * An instance of this class should be obtained by parsing the YAML data/config file see {@link org.letsconfide.config.ConfigParser#parse(File, DeviceFactory)}
 *
 */
public class SensitiveDataManager
{

    private final ConfigHeaders headers;

    /**
     * A map whose values are padded with PKCS#7 padding and encrypted with an ephemeral key.
     */
    private final Map<String, byte[]> dataMap;
    private final DeviceFactory factory;
    private final HostDEK ephemeralKey;
    private final EncryptedData encryptedData;


    public SensitiveDataManager(ConfigHeaders headers, DeviceFactory factory, EncryptedData encryptedData)
    {
        this.headers = headers;
        this.factory = factory;
        try (SecurityDevice device = factory.newDevice(headers, encryptedData.getDeviceTokens()))
        {
            ephemeralKey = HostDEK.from(false, encryptedData.getEncKey(), encryptedData.getSeed());
            this.encryptedData = encryptedData;
            dataMap = fromSizedByteArrayList(device, ephemeralKey, encryptedData);
        }
    }

    public SensitiveDataManager(ConfigHeaders headers, DeviceFactory factory, Map<String, byte[]> unEncryptedData)
    {
        this.headers = headers;
        this.factory = factory;
        Map.Entry<SecurityDevice, List<byte[]>> created = factory.newDevice(headers);
        try (SecurityDevice device = created.getKey())
        {
            ephemeralKey = HostDEK.generateNew(true, device);
            Map<String, byte[]> map = new HashMap<>();
            encryptedData = toEncryptedData(unEncryptedData, device, ephemeralKey, created.getValue(), map);
            dataMap = map;
        }
    }

    private static EncryptedData toEncryptedData(Map<String, byte[]> unEncryptedData, SecurityDevice device, HostDEK ephemeralKey, List<byte[]> deviceTokens, Map<String, byte[]> dataMapToUpdate)
    {
        List<byte[]> result = new ArrayList<>();

        byte[] seed = device.getRandomBytes(SEED_SIZE);
        HostDEK storageKey = HostDEK.generateNew(false, device, seed);

        try (HostDEK.ResolvedDek resolvedEphKey = ephemeralKey.newResolvedDek(device))
        {
            for (Map.Entry<String, byte[]> entry : unEncryptedData.entrySet())
            {
                byte[] paddedValue = addPKCS7Padding(entry.getValue());

                dataMapToUpdate.put(entry.getKey(), resolvedEphKey.encrypt(paddedValue));
                byte[] paddedKey = addPKCS7Padding(entry.getKey().getBytes(StandardCharsets.UTF_8));
                result.add(paddedKey);
                result.add(paddedValue);
            }
        }
        byte[] resultArray = storageKey.encrypt(device, Utils.createSizedByteArray(result));
        return new EncryptedData(seed, storageKey.getEncryptedKey(), resultArray, deviceTokens);
    }

    /**
     * Converts the supplied encrypted data in to a Map, keys in the resultant Map
     * are not encrypted, values are encrypted using the supplied ephemeralKey.
     *
     * @param device        The security device used to decrypt the encryptedData
     * @param ephemeralKey  data encryption key that will be used to encrypt values in the output Map
     * @param encryptedData Map data encrypted using the security device
     * @return The Map containing keys and the corresponding encrypted values
     */
    private static Map<String, byte[]> fromSizedByteArrayList(SecurityDevice device, HostDEK ephemeralKey, EncryptedData encryptedData)
    {
        HostDEK storageDek = HostDEK.from(false, encryptedData.getEncKey(), encryptedData.getSeed());
        byte[] sizedByteArrayList = storageDek.decrypt(device, encryptedData.getCipherData());
        Map<String, byte[]> result = new HashMap<>();
        List<byte[]> list = Utils.splitSizedByteArray(sizedByteArrayList);
        int listSize = list.size();
        if(listSize%2 != 0)
        {
            throw new LetsConfideException("EncryptedData do not contain key value pairs");
        }
        try (HostDEK.ResolvedDek resolvedEphKey = ephemeralKey.newResolvedDek(device))
        {
            for(int i=1; i < listSize; i+=2)
            {
                String key = new String(removePKCS7Padding(list.get(i - 1)), StandardCharsets.UTF_8);
                // The value being inserted should have PKCS#7 padding.
                result.put(key, resolvedEphKey.encrypt(list.get(i)));
            }
        }
        return result;
    }

    /**
     * Adds PKCS#7 padding to the given array of bytes
     * @param bytes un padded array of bytes
     * @return padded array of bytes
     */
    private static byte[] addPKCS7Padding(byte[] bytes)
    {
        // Make this configurable
        int BLOCK_SIZE = 32;
        byte[] result = new byte[bytes.length + (BLOCK_SIZE - (bytes.length % BLOCK_SIZE))];
        System.arraycopy(bytes, 0, result, 0, bytes.length);
        new PKCS7Padding().addPadding(result, bytes.length);
        return result;
    }

    /**
     * Removes PKCS#7 padding from the given array of bytes.
     * Note that, this method erases the input array.
     * @param bytes padded array of bytes
     * @return un padded array of bytes
     */
    private static byte[] removePKCS7Padding(byte[] bytes)
    {
        try
        {
            byte[] result = new byte[bytes.length - new PKCS7Padding().padCount(bytes)];
            System.arraycopy(bytes, 0, result, 0, result.length);
            return result;
        }
        catch (InvalidCipherTextException e)
        {
            throw new LetsConfideException("Unable to remove padding in encrypted data");
        }
        finally
        {
            Utils.erase(bytes);
        }
    }

    /**
     * @return Configuration headers
     */
    public ConfigHeaders getHeaders()
    {
        return headers;
    }

    /**
     * @return Encrypted data
     */
    public EncryptedData getEncryptedData()
    {
        return encryptedData;
    }

    public DataAccessSession startDataAccessSession()
    {
        return new DataAccessSession();
    }


    /**
     * A session used to access encrypted data.<BR>
     * When initializing a session the "ephemeral host based data encryption key" is decrypted using the device (TPM),
     * therefore initialization is considerably slow (hundreds of milliseconds). The performance cost of accessing
     * encrypted data thereafter is significantly lower (all operations are performed on the host).
     */
    public class DataAccessSession implements LetsConfideCloseable
    {
        private final HostDEK.ResolvedDek resolvedKey;

        /**
         * Initializes the session by decrypting the ephemeral host data encryption key using the device.
         */
        private DataAccessSession()
        {
            try(SecurityDevice device = factory.newDevice(headers, encryptedData.getDeviceTokens()))
            {
                resolvedKey = ephemeralKey.newResolvedDek(device);
            }
        }

        /**
         * Decrypts the value in the data Map corresponding to the given key, using the
         * decrypted "ephemeral host based data encryption key".
         * @param key A Key in the data Map
         * @return Decrypted value corresponding to the given key in the Map
         */
        public char[] decrypt(String key)
        {
            byte[] encData = dataMap.get(key);
            if (encData == null)
            {
                // Do not reveal the name of the key.
                throw new LetsConfideException("Key not found");
            }
            byte[] bytes = removePKCS7Padding(resolvedKey.decrypt(encData));
            try
            {
                return StandardCharsets.UTF_8.decode(ByteBuffer.wrap(bytes)).array();
            }
            finally
            {
                Utils.erase(bytes);
            }
        }

        /**
         * Removes the decrypted "ephemeral host based data encryption key" from memory.
         */
        @Override
        public void close() throws LetsConfideException
        {
            resolvedKey.close();
        }
    }


}
