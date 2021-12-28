package org.letsconfide.config;

import org.letsconfide.LetsConfideException;
import org.letsconfide.SensitiveDataManager;
import org.letsconfide.Utils;
import org.letsconfide.config.ConfigHeaders.CipherType;
import org.letsconfide.config.ConfigHeaders.HashType;
import org.letsconfide.platform.DeviceFactory;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.error.Mark;
import org.yaml.snakeyaml.events.Event;
import org.yaml.snakeyaml.events.ScalarEvent;

import javax.annotation.CheckForNull;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Stream;

import static java.nio.file.StandardOpenOption.READ;
import static org.letsconfide.Utils.createFieldNameNotDefinedException;
import static org.letsconfide.Utils.ensureIsDefined;
import static org.letsconfide.config.ConfigHeaders.DEFAULT;
import static org.yaml.snakeyaml.events.Event.ID.*;

/**
 * Responsible for parsing the input YAML file and producing an instance of  a {@link SensitiveDataManager}.
 * If the input file is unencrypted then after successfully parsing the input file, this parser will encrypt it.
 */
public class ConfigParser
{

    private static final String HEADERS_KEY = "headers";
    private static final String PRIMARY_KEY_TYPE_KEY = "primaryKeyType";
    private static final String STORAGE_KEY_TYPE_KEY = "storageKeyType";
    private static final String EPHEMERAL_KEY_TYPE_KEY = "ephemeralKeyType";
    private static final String PCR_SELECTION_KEY = "pcrSelection";
    private static final String PCR_HASH_KEY = "pcrHash";


    private static final String DATA_KEY = "data";
    private static final String ENCRYPTED_DATA_KEY = "encryptedData";
    private static final String SEED_KEY = "seed";
    private static final String ENCRYPTED_KEY_KEY = "encryptedKey";
    private static final String CIPHER_DATA_KEY = "cipherData";
    private static final String DEVICE_TOKENS_KEY = "deviceTokens";

    /**
     * Starts parsing the input file.
     * @param file The input file
     * @param deviceFactory A device factory
     * @return The resultant {@link SensitiveDataManager}
     */
    public SensitiveDataManager parse(File file, DeviceFactory deviceFactory) throws IOException
    {
        ConfigHeaders headers;
        Map<String, byte[]> unencryptedData;
        EncryptedData encryptedData;
        SensitiveDataManager manager;
        try (ConfigInputStream input = new ConfigInputStream(Files.newInputStream(file.toPath(), READ)))
        {
            Yaml yaml = new Yaml();
            Iterator<Event> eventIter = yaml.parse(new InputStreamReader(input, StandardCharsets.UTF_8)).iterator();
            consumeStreamStart(eventIter);
            Event currentEvent = checkAndGetNextEvent(eventIter, Scalar);
            headers = DEFAULT;
            if (HEADERS_KEY.equals(getScalarValue(currentEvent)))
            {
                headers = readHeaders(eventIter);
                currentEvent = checkAndGetNextEvent(eventIter, Scalar);
            }
            if (DATA_KEY.equals(getScalarValue(currentEvent)))
            {
                unencryptedData = readData(eventIter);
                manager = new SensitiveDataManager(headers, deviceFactory, unencryptedData);
                writeEncryptedYAML(manager.getEncryptedData(), headers, file.toPath());
            }
            else
            {
                if (!ENCRYPTED_DATA_KEY.equals(getScalarValue(currentEvent)))
                {
                    throw createFieldNameNotDefinedException("encryptedData");
                }
                encryptedData = readEncryptedData(eventIter);
                manager = new SensitiveDataManager(headers, deviceFactory, Objects.requireNonNull(encryptedData));
            }
            consumeStreamEnd(eventIter);
        }
        return manager;
    }

    private static void consumeStreamStart(Iterator<Event> eventIter)
    {
        checkAndGetNextEvent(eventIter, StreamStart);
        checkAndGetNextEvent(eventIter, DocumentStart);
        checkAndGetNextEvent(eventIter, MappingStart);
    }

    private static void consumeStreamEnd(Iterator<Event> eventIter)
    {
        checkAndGetNextEvent(eventIter, MappingEnd);
        checkAndGetNextEvent(eventIter, DocumentEnd);
        checkAndGetNextEvent(eventIter, StreamEnd);
    }

    /**
     * Reads encrypted data from the input YAML.
     * @param eventIter YAML iterator
     * @return the encrypted dada
     */
    private EncryptedData readEncryptedData(Iterator<Event> eventIter)
    {
        byte[] cipherData = null;
        byte[] seed = null;
        byte[] encKey = null;
        List<byte[]> deviceTokens = null;
        for (MappingIterator iter = new MappingIterator(eventIter); iter.hasNext(); )
        {
            String key = iter.next();
            switch (key)
            {
                case SEED_KEY:
                    seed = iter.nextByteArray();
                    break;
                case ENCRYPTED_KEY_KEY:
                    encKey = iter.nextByteArray();
                    break;
                case CIPHER_DATA_KEY:
                    cipherData = iter.nextByteArray();
                    break;
                case DEVICE_TOKENS_KEY:
                    deviceTokens = Utils.splitSizedByteArray(iter.nextByteArray());
                    break;
                default:

                    throw createParseException("Invalid key " + key, iter.getCurrentLineStart());
            }
        }
        return new EncryptedData(ensureIsDefined(seed, SEED_KEY), ensureIsDefined(encKey, ENCRYPTED_KEY_KEY), ensureIsDefined(cipherData, CIPHER_DATA_KEY), ensureIsDefined(deviceTokens, DEVICE_TOKENS_KEY));
    }

    private static String getScalarValue(Event event)
    {
        assert event.getEventId() == Scalar;
        return ((ScalarEvent) event).getValue();
    }

    private static Event checkAndGetNextEvent(Iterator<Event> eventIterable, Event.ID firstExpectedId, Event.ID... moreExpectedIds)
    {
        if (!eventIterable.hasNext())
        {
            throw createParseException("Unexpected end of config file", null);
        }
        Event result = eventIterable.next();
        validateEvent(result, firstExpectedId, moreExpectedIds);
        return result;
    }

    private static void validateEvent(Event event, Event.ID firstExpectedId, Event.ID... moreExpectedIds)
    {
        if (Stream.concat(Stream.of(firstExpectedId), Stream.of(moreExpectedIds)).noneMatch(event.getEventId()::equals))
        {
            String message = "Unexpected entry";
            if (event.getEventId() == Alias)
            {
                message += ": YAML aliases are not supported";
            }
            throw createParseException(message, event.getStartMark());
        }
    }

    /**
     * Reads config headers from the input YAML
     * @param eventIterable YAMl iterator
     * @return The config headers
     */
    private ConfigHeaders readHeaders(Iterator<Event> eventIterable)
    {
        CipherType primaryKeyType = DEFAULT.getPrimaryKeyType();
        CipherType storageKeyType = DEFAULT.getStorageKeyType();
        CipherType ephemeralKeyType = DEFAULT.getEphemeralKeyType();

        HashType pcrHash = DEFAULT.getPcrHash();
        int pcrSelection = DEFAULT.getPcrSelection();
        for (MappingIterator it = new MappingIterator(eventIterable); it.hasNext(); )
        {
            String key = it.nextKey();
            switch (key)
            {
                case PRIMARY_KEY_TYPE_KEY:
                    primaryKeyType = CipherType.valueOf(it.nextValue());
                    break;
                case STORAGE_KEY_TYPE_KEY:
                    storageKeyType = CipherType.valueOf(it.nextValue());
                    break;
                case EPHEMERAL_KEY_TYPE_KEY:
                    ephemeralKeyType = CipherType.valueOf(it.nextValue());
                    break;
                case PCR_SELECTION_KEY:
                    pcrSelection = Integer.parseInt(it.nextValue());
                    break;
                case PCR_HASH_KEY:
                    pcrHash = HashType.valueOf(it.nextValue());
                    break;
                default:
                    throw createParseException("Invalid config header", it.getCurrentLineStart());
            }
        }
        return new ConfigHeaders(primaryKeyType, storageKeyType, ephemeralKeyType, pcrSelection, pcrHash);
    }

    Map<String, byte[]> readData(Iterator<Event> eventIterable)
    {
        Map<String, byte[]> dataMap = new HashMap<>();
        for (MappingIterator it = new MappingIterator(eventIterable); it.hasNext(); )
        {
            dataMap.put(it.nextKey(), it.nextValue().getBytes(StandardCharsets.UTF_8));
        }
        return dataMap;
    }


    /**
     * An iterator to iterate through YAML mapping.
     */
    private static class MappingIterator implements Iterator<String>
    {
        private final Iterator<Event> eventIter;

        private final Set<String> keySet = new HashSet<>();
        private Event nextEntry;
        // TODO: @CheckForNull (include the annotations)
        private Mark currentLineStart;

        MappingIterator(Iterator<Event> eventIter)
        {
            this.eventIter = eventIter;
            checkAndGetNextEvent(eventIter, MappingStart);
            nextEntry = getNextEntry(eventIter);
        }

        private static Event getNextEntry(Iterator<Event> iter)
        {
            return checkAndGetNextEvent(iter, Scalar, MappingEnd, SequenceStart, SequenceEnd);
        }

        private Mark getCurrentLineStart()
        {
            return Objects.requireNonNull(currentLineStart);
        }

        @Override
        public boolean hasNext()
        {
            return nextEntry.getEventId() == Scalar || nextEntry.getEventId() == SequenceStart;
        }

        private Event getNextEntry(Event.ID firstExpectedId, Event.ID... moreExpectedIds)
        {
            currentLineStart = nextEntry.getStartMark();
            validateEvent(nextEntry, firstExpectedId, moreExpectedIds);
            Event result = nextEntry;
            nextEntry = getNextEntry(eventIter);
            return result;
        }

        @Override
        public String next()
        {
            return getScalarValue(getNextEntry(Scalar, MappingEnd, SequenceStart));
        }

        /**
         * @return The next key in the current YAML mapping
         */
        private String nextKey()
        {
            String result = next();
            if (!keySet.add(result))
            {
                throw createParseException("Duplicate key", getCurrentLineStart());
            }
            return result;
        }

        /**
         * @return The next value in the current YAML mapping.
         */
        private String nextValue()
        {
            return next();
        }

        /**
         * @return The next byte array stored in the YAML mapping
         */
        private byte[] nextByteArray()
        {
            getNextEntry(SequenceStart);
//            checkAndGetNextEvent(eventIter, SequenceStart);
            int size = 0;
            List<byte[]> list = new ArrayList<>();
            while (true)
            {
                Event event = getNextEntry(Scalar, SequenceEnd);
                if (event.getEventId() == Scalar)
                {

                    byte[] bytes = Base64.getDecoder().decode(getScalarValue(event));
                    size += bytes.length;
                    list.add(bytes);
                }
                else
                {
                    assert event.getEventId() == SequenceEnd;
                    break;
                }
            }
            ByteBuffer buffer = ByteBuffer.allocate(list.stream().mapToInt(it -> it.length).sum());
            list.forEach(buffer::put);
            byte[] result = new byte[buffer.position()];
            buffer.rewind();
            buffer.get(result);
            return result;
        }
    }

    /**
     * Writes config headers and encrypted data to the given YAML file.
     * @param encryptedData Encrypted data
     * @param headers config headers
     * @param yamlFile The YAML file
     */
    private void writeEncryptedYAML(EncryptedData encryptedData, ConfigHeaders headers, Path yamlFile)
    {
        Map<String, Map<String, Object>> root = new LinkedHashMap<>();

        Map<String, Object> heads = new LinkedHashMap<>();
        heads.put(PRIMARY_KEY_TYPE_KEY, headers.getPrimaryKeyType().name());
        heads.put(STORAGE_KEY_TYPE_KEY, headers.getStorageKeyType().name());
        heads.put(EPHEMERAL_KEY_TYPE_KEY, headers.getEphemeralKeyType().name());
        heads.put(PCR_SELECTION_KEY, Integer.toString(headers.getPcrSelection()));
        heads.put(PCR_HASH_KEY, headers.getPcrHash().name());
        root.put(HEADERS_KEY, heads);
        Map<String, Object> encData = new LinkedHashMap<>();

        root.put(ENCRYPTED_DATA_KEY, encData);
        encData.put(SEED_KEY, splitToYamlArray(encryptedData.getSeed()));
        encData.put(ENCRYPTED_KEY_KEY, splitToYamlArray(encryptedData.getEncKey()));
        encData.put(CIPHER_DATA_KEY, splitToYamlArray(encryptedData.getCipherData()));
        encData.put(DEVICE_TOKENS_KEY, splitToYamlArray(Utils.createSizedByteArray(encryptedData.getDeviceTokens())));
        try
        {
            Utils.writeToYamlFile(root, yamlFile);
        }
        catch (LetsConfideException e)
        {
            throw new LetsConfideException("Unable to write the encrypted YAML file.", e);
        }
    }

    /**
     * Splits an array of bytes into chunks of base64 encoded 32 byte arrays.
     * @param bytes bytes  to be split
     * @return A list of base64 encoded 32 byte chunks of the original array
     */
    private List<String> splitToYamlArray(byte[] bytes)
    {
        int segmentSize = 32;
        int fullSegments = bytes.length / segmentSize;
        List<String> result = new ArrayList<>(fullSegments + 1);
        for (int i = 0; i < fullSegments; i++)
        {
            byte[] part = new byte[segmentSize];
            System.arraycopy(bytes, i * segmentSize, part, 0, segmentSize);
            result.add(Base64.getEncoder().encodeToString(part));
        }
        int rest = bytes.length % segmentSize;
        if (rest > 0)
        {
            byte[] last = new byte[rest];
            System.arraycopy(bytes, fullSegments * segmentSize, last, 0, rest);
            result.add(Base64.getEncoder().encodeToString(last));
        }
        return result;
    }

    /**
     * Creates a parse exception.
     * @param message Exception message
     * @param currentPos Position in the file being parsed
     * @return The parse exception
     */
    private static LetsConfideException createParseException(String message, @CheckForNull Mark currentPos)
    {
        StringBuilder sb = new StringBuilder("Error parsing YAML file: " ).append(message);
        if(currentPos != null)
        {
            sb.append(" at line ").append(currentPos.getLine());
        }
        return new LetsConfideException(sb.toString());
    }

}