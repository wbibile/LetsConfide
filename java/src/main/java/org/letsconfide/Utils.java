package org.letsconfide;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import javax.annotation.Nullable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;

/**
 * Contains general utility methods.
 */
public class Utils
{

    private static final int MAX_ELM_SIZE = Character.MAX_VALUE;

    /**
     * Tests whether the unsigned value represented by the given byte sequence is zero.
     *
     * @param bytes Array containing the byte sequence
     * @param start start of the byte sequence in the array (inclusive)
     * @param end   end of the byte sequence in the array (exclusive)
     * @return true of the byte sequence is zero.
     */
    public static boolean isZero(byte[] bytes, int start, int end)
    {
        assert start < end : "Stat is greater than end";
        assert end < bytes.length : "End is out of range";
        boolean result = true;
        for (int i = start; i < end; i++)
        {
            if (bytes[i] != (byte) 0)
            {
                result = false;
                break;
            }
        }
        return result;
    }

    /**
     * Erases a byte sequence.
     *
     * @param bytes The byte sequence to erase.
     */
    public static void erase(byte[] bytes)
    {
         Arrays.fill(bytes, (byte) 0);
    }

    /**
     * Checks whether the given field read from the LetsConfide configuration is defined.
     *
     * @param value the value that should have been read
     * @param fieldName the field name
     * @return the value
     * @throws LetsConfideException if the value is not defined
     */
    public static <T> T ensureIsDefined(@Nullable T value, String fieldName) throws LetsConfideException
    {
        if (value == null)
        {
            throw createFieldNameNotDefinedException(fieldName);
        }
        return value;
    }

    /**
     * Creates an exception that indicates a property is not defined.
     * @param propertyName The property name
     * @return the created exception
     */
    public static LetsConfideException createFieldNameNotDefinedException(String propertyName)
    {
        return new LetsConfideException("Property \"" + propertyName + "\"" + " is not defined");
    }

    /**
     * Creates a YAML object suitable for dumping data.
     * @return The YAML object
     */
    // Visible for testing
    public static Yaml newYamlInstance()
    {
        DumperOptions options = new DumperOptions();
        options.setIndent(2);
        options.setPrettyFlow(true);
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        return new Yaml(options);
    }

    /**
     * Dumps the content of the given Map into to a YAML file.
     * @param map The Map whose content is to be dumped
     * @param yamlFile The file where the content is dumped
     */
    public static <K, V> void writeToYamlFile(Map<K, V> map, Path yamlFile) throws LetsConfideException
    {
        try
        {
            Files.write(yamlFile, newYamlInstance().dump(map).getBytes(StandardCharsets.UTF_8), WRITE, TRUNCATE_EXISTING);
        }
        catch (IOException e)
        {
            throw new LetsConfideException("Unable write to YAML file", e);
        }
    }

    /**
     * Produces the SHA256 hash of the given array of bytes.
     * @param bytes Array of bytes to hash
     * @return array if 32 bytes constituting the SHA256 hash
     */
    public static byte[] hashHsa256(byte[] bytes)
    {
        try
        {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new LetsConfideException("SHA256 not supported.");
        }
    }

    /**
     * Encrypts or decrypts the given data using AES in GCM mode.
     *
     * @param decrypt        Whether the text is being decrypted
     * @param key            the AES key
     * @param iv             initialization vector used by GCM
     * @param associatedText extra text used by GCM mode (used in its MAC validation)
     * @param data           data to be encrypted or decrypted
     * @return encrypted or decrypted data
     */
    public static byte[] aesGsmEncryptDecrypt(boolean decrypt, byte[] key, byte[] iv, byte[] associatedText, byte[] data) throws InvalidCipherTextException
    {
        KeyParameter keyParam = new KeyParameter(key);
        // block size for AES is 16 bytes,

        CipherParameters params = new AEADParameters(keyParam, 128, iv, associatedText);

        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());

        cipher.reset();
        cipher.init(!decrypt, params);

        byte[] buf = new byte[cipher.getOutputSize(data.length)];
        int len = cipher.processBytes(data, 0, data.length, buf, 0);
        len += cipher.doFinal(buf, len);

        byte[] result;
        if (decrypt)
        {
            result = new byte[len];
            System.arraycopy(buf, 0, result, 0, len);
        }
        else
        {
            result = buf;
        }
        return result;
    }

    /**
     * Splits a larger array of bytes consisting of concatenated sized byte arrays.<BR>
     *  Where: <BR>
     * (n)thArraySize: Two bytes encoding the size of the n<sup>th</sup> sub array as an unsigned big-endian integer<BR>
     * (n)thByteArray: Content of the n<sup>th</sup> array and <BR>
     * '+' (Plus sign)             :represents byte array concatenation<BR><BR>
     *  inputBytes = (0)thArraySize+(0)thByteArray+(1)thArraySize+(1)thByteArray+...
     *  +(n-2)thArraySize+(n-2)thByteArray+(n-1)thArraySize+(n-1)thByteArray
     * @param inputBytes larger array containing sized byte arrays
     * @return List of constituent byte arrays
     */
    public static List<byte[]> splitSizedByteArray(byte[] inputBytes) throws LetsConfideException
    {
        List<byte[]> result = new ArrayList<>(2);
        int size;
        for (int i = 0; i < inputBytes.length; )
        {
            size = getSizeOfNextEntry(inputBytes, i);
            if (size < 0)
            {
                throw new LetsConfideException("Invalid sized byte array, negative size " + size);
            }
            // Advance i past the size of the two bytes that specify the size of the segment.
            i += 2;
            if (inputBytes.length < (i + size))
            {
                throw new LetsConfideException("Invalid sized byte array, byte segment size " + size + " at index " + i + " is too large");
            }
            byte[] sizedSegment = new byte[size];
            System.arraycopy(inputBytes, i, sizedSegment, 0, size);
            result.add(sizedSegment);
            // Advanced past the sizedSegment.
            i += size;
        }
        return result;
    }

    /**
     * Get the size of the next logical byte array within a larger array of size bytes.
     * @param sizedByteArrayList sized byte array list
     * @param start              Start of the next logical byte array (including the size bytes)
     * @return The size of the next logical byte array (within the larger array)
     */
    private static int getSizeOfNextEntry(byte[] sizedByteArrayList, int start)
    {
        int result;
        if (sizedByteArrayList.length <= start)
        {
            assert sizedByteArrayList.length == start;
            // No more data
            result = Integer.MIN_VALUE;
        }
        else
        {
            assert sizedByteArrayList.length - start > 2 : "Invalid size: " + sizedByteArrayList.length + ", and start: " + start;
            byte[] sizeBytes = new byte[4];
            System.arraycopy(sizedByteArrayList, start, sizeBytes, 2, 2);

            result = ByteBuffer.wrap(sizeBytes).getInt();
            if (result <= 0)
            {
                throw new LetsConfideException("Invalid size");
            }
        }
        return result;
    }

    /**
     * Combines a list of byte arrays into a single byte array.<BR>
     * This is the inverse of {@link #splitSizedByteArray(byte[])}.
     * @param arrayComponentList Array components
     * @return The combined array
     */
    public static byte[] createSizedByteArray(List<byte[]> arrayComponentList)
    {
        // The size of the resultant array is the combined size of the list of component arrays
        // plus an additional two bytes for each component array (to represent the size).
        byte[] result = new byte[arrayComponentList.stream().mapToInt(it -> it.length).sum()+arrayComponentList.size()*2];
        int index = 0;
        for (byte[] bytes : arrayComponentList)
        {
            byte[] sizedBytes = sizedByteArray(bytes);
            System.arraycopy(sizedBytes,0, result, index, sizedBytes.length);

            Utils.erase(sizedBytes);
            index+=sizedBytes.length;
        }
        return result;
    }

    /**
     * Encodes the size of the given byte array using the following method.
     * output-bytes =[two, size encoded bytes][input-bytes]
     * The two size encoded bytes encode the size of the input byte array as an unsigned big-endian integer.
     * @param inputBytes byte array before encoding the size
     * @return output bytes with encoded size
     */
    private static byte[] sizedByteArray(byte[] inputBytes)
    {
        int size = inputBytes.length;
        if (size > MAX_ELM_SIZE) {
            throw new LetsConfideException("Data elements greater than " + MAX_ELM_SIZE + " are not supported.");
        }
        // allocate the output bytes.
        byte[] result = new byte[inputBytes.length + 2];

        // Encode the size of the input-bytes
        result[1] = (byte)(size & 0xFF);
        result[0] = (byte)((size >> 8) & 0xFF);

        // Copy the input bytes to the remaining output bytes.
        System.arraycopy(inputBytes,0,result,2, inputBytes.length);
        return result;
    }

}
