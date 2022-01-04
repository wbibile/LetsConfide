package org.letsconfide;

import org.junit.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.letsconfide.config.ConfigHeaders;
import org.letsconfide.config.ConfigHeaders.CipherType;
import org.letsconfide.config.ConfigHeaders.HashType;
import org.letsconfide.config.ConfigParser;
import org.letsconfide.platform.DeviceFactory;
import org.letsconfide.platform.FakeDeviceFactory;
import org.letsconfide.platform.tpm.TPMDeviceFactory;
import org.yaml.snakeyaml.Yaml;
import tss.*;
import tss.tpm.TPM_CC;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

@RunWith(Parameterized.class)
public class TestMain
{
    enum DeviceType
    {FAKE, SIMULATOR, REAL}

    private static final DeviceType TEST_MODE;
    private static final DeviceFactory FACTORY;

    private static final Pattern CIPHER_PATTERN;
    private final TestConfig testConfig;
    private static final Pattern HASH_PATTERN;


    static
    {
        TEST_MODE = DeviceType.valueOf(System.getProperty("org.letsconfide.test.DeviceType", DeviceType.FAKE.name()));
        String cipherRegex = System.getProperty("org.letsconfide.test.CipherRegex");
        if (TEST_MODE == DeviceType.FAKE && cipherRegex != null)
        {
            // CipherRegex not valid when using device.
            throw new LetsConfideException("CipherRegex not valid when using device " + DeviceType.FAKE);
        }
        CIPHER_PATTERN = Pattern.compile(cipherRegex == null ? ".*" : cipherRegex);
        String hashRegex = System.getProperty("org.letsconfide.test.HashRegex", ".*");
        HASH_PATTERN = Pattern.compile(hashRegex);

        FACTORY = getDeviceFactory();
    }

    private static DeviceFactory getDeviceFactory()
    {
        switch (TEST_MODE)
        {
            case FAKE:
                return new FakeDeviceFactory();
            case SIMULATOR:
                return new TPMDeviceFactory(TpmSimulator::new);
            case REAL:
                return TPMDeviceFactory.PLATFORM_INSTANCE;
            default:
                throw new LetsConfideException("org.letsconfide.test.DeviceType is invalid");
        }
    }

    @AfterClass
    public static void afterClass()
    {
        TpmSimulator.closeDevice();
    }

    @Parameterized.Parameters
    public static Collection<TestConfig[]> getTestParams()
    {
        List<TestConfig[]> result = new ArrayList<>();
        switch (TEST_MODE)
        {
            case FAKE:
                result.add(wrapInArray(ConfigHeaders.DEFAULT));
                break;
            case SIMULATOR:
            case REAL:
                getAllCipherHashPermutations().stream().map(TestMain::wrapInArray).forEach(result::add);
                break;
        }
        return result;
    }

    private static List<ConfigHeaders> getAllCipherHashPermutations()
    {
        CipherType[] allCiphers = CipherType.values();
        HashType[] allHashes = HashType.values();
        int numCiphers = allCiphers.length;
        int numHashes = allHashes.length;
        List<ConfigHeaders> result = new ArrayList<>((numCiphers * numCiphers * numCiphers) + numHashes);
        for (CipherType prim : allCiphers)
        {
            if (ignoreCipherType(prim))
            {
                continue;
            }
            for (CipherType storage : allCiphers)
            {
                if (ignoreCipherType(storage))
                {
                    continue;
                }
                for (CipherType ephemeral : allCiphers)
                {
                    if (ignoreCipherType(ephemeral))
                    {
                        continue;
                    }
                    for (HashType pcrHash : allHashes)
                    {
                        if (HASH_PATTERN.matcher(pcrHash.name()).matches())
                        {
                            result.add(new ConfigHeaders(prim, storage, ephemeral, ConfigHeaders.DEFAULT.getPcrSelection(), pcrHash));
                        }
                    }
                }
            }
        }
        if (result.isEmpty())
        {
            throw new LetsConfideException("No tests for current criteria");
        }
        return result;
    }

    public TestMain(TestConfig testConfig)
    {
        this.testConfig = testConfig;
    }

    @Before
    public void before()
    {
        testConfig.init();
        Assert.assertNotNull(testConfig.getManagerFromRawData());
    }

    @After
    public void after()
    {
        Assert.assertEquals(0, TpmSimulator.openSimulators );
    }

    private static boolean ignoreCipherType(CipherType type)
    {
        return !CIPHER_PATTERN.matcher(type.name()).matches();
    }

    private static TestConfig[] wrapInArray(ConfigHeaders headers)
    {
        TestConfig[] result = new TestConfig[1];
        result[0] = new TestConfig(headers);
        return result;
    }

    @Test
    public void testHeadersFromRaw()
    {
        assertHeaders(testConfig.getManagerFromRawData());
    }

    @Test
    public void testHeadersFromEncrypted()
    {
        assertHeaders(testConfig.getManagerFromEncryptedData());
    }

    private void assertHeaders(SensitiveDataManager m)
    {
        ConfigHeaders h = m.getHeaders();
        Assert.assertEquals(CipherType.valueOf(testConfig.getHeaders().get("primaryKeyType")), h.getPrimaryKeyType());
        Assert.assertEquals(CipherType.valueOf(testConfig.getHeaders().get("storageKeyType")), h.getStorageKeyType());
        Assert.assertEquals(Utils.parseInt(testConfig.getHeaders().get("pcrSelection"), LetsConfideException::new), h.getPcrSelection());
        Assert.assertEquals(HashType.valueOf(testConfig.getHeaders().get("pcrHash")), h.getPcrHash());
    }

    @Test
    public void testPasswordsFromRaw()
    {
        assertPasswords(testConfig.getManagerFromRawData());
    }

    @Test
    public void testPasswordsFromEncrypted()
    {
        assertPasswords(testConfig.getManagerFromEncryptedData());
    }

    private void assertPasswords(@SuppressWarnings("unused") SensitiveDataManager m)
    {
        try (SensitiveDataManager.DataAccessSession session = m.startDataAccessSession())
        {
            for (Map.Entry<String, String> entry : testConfig.getData().entrySet())
            {
                Assert.assertArrayEquals(entry.getValue().toCharArray(), session.decrypt(entry.getKey()));
            }
        }
    }

    @Test
    public void testKeyNotFoundFromRaw()
    {
        assertKeyNotFound(testConfig.getManagerFromRawData());
    }

    @Test
    public void testKeyNotFoundFromEncrypted()
    {
        assertKeyNotFound(testConfig.getManagerFromEncryptedData());
    }

    @SuppressWarnings("unused")
    private void assertKeyNotFound(SensitiveDataManager m)
    {
        try (SensitiveDataManager.DataAccessSession session = m.startDataAccessSession())
        {
            try
            {
                session.decrypt("foobar");
                Assert.fail("Undefined key must yield an exception");
            }
            catch (LetsConfideException e)
            {
                Assert.assertEquals("Key not found", e.getMessage());
            }
        }
    }

    /**
     * Represents a configuration for a group of tests.
     */
    private static class TestConfig
    {
        private final ConfigHeaders configHeaders;
        private final Map<String, String> headers = new LinkedHashMap<>();
        private final  Map<String, String> data = new LinkedHashMap<>();
        private volatile Path yamlFile;
        private volatile SensitiveDataManager managerFromRawData;
        private volatile SensitiveDataManager managerFromEncryptedData;
        private final AtomicBoolean uninitialized = new AtomicBoolean(true);

        TestConfig(ConfigHeaders configHeaders)
        {
            this.configHeaders = configHeaders;
        }

        public void init()
        {
            if (!uninitialized.compareAndSet(true, false))
            {
                return;
            }
            if (FACTORY instanceof TPMDeviceFactory)
            {
                ((TPMDeviceFactory) FACTORY).reset();
            }
            Map<String, Object> root = new LinkedHashMap<>();
            headers.put("primaryKeyType", configHeaders.getPrimaryKeyType().name());
            headers.put("storageKeyType", configHeaders.getStorageKeyType().name());
            headers.put("ephemeralKeyType", configHeaders.getEphemeralKeyType().name());
            headers.put("pcrSelection", String.valueOf(configHeaders.getPcrSelection()));
            headers.put("pcrHash", configHeaders.getPcrHash().name());

            data.put("primary_passwd", "ub,KbVsh/XUj~=~F#");
            data.put("my_password", "U7MeKLkU8te4FbZZ");
            data.put("database_pwd", "4R4SHY97sDv9GnH7");
            data.put("hello", "fSGvnu6b4VSGUFFm");
            data.put("weak", "0123456789");
            data.put("empty", "");
            data.put("", "empty");
            data.put("16bytePwd", "0123456789abcdef");
            data.put("32bytePwd", "0123456789abcdef0123456789abcdef");
            data.put("48bytePwd", "0123456789abcdef0123456789abcdef0123456789abcdef");
            data.put("64bytePwd", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
            data.put("96bytePwd", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
            data.put("128bytePwd", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

            root.put("headers", headers);
            root.put("data", data);
            try
            {
                yamlFile = Files.createTempFile("testYaml", ".yaml");
                Utils.writeToYamlFile(root, yamlFile);

                managerFromRawData = new ConfigParser().parse(yamlFile.toFile(), FACTORY);
                assertYamlFileIsEncrypted();
                managerFromEncryptedData = new ConfigParser().parse(yamlFile.toFile(), FACTORY);
            }
            catch (IOException e)
            {
                throw new LetsConfideException(e);
            }
        }


        private void assertYamlFileIsEncrypted() throws IOException
        {
            try (InputStreamReader reader = new InputStreamReader(Files.newInputStream(yamlFile, StandardOpenOption.READ), StandardCharsets.UTF_8))
            {
                Map<String, Object> m = new Yaml().load(reader);
                Assert.assertNull(m.get("data"));
                //noinspection unchecked
                Map<String, Object> encData = (Map<String, Object>) m.get("encryptedData");
                Assert.assertNotNull(encData.get("seed"));
                Assert.assertNotNull(encData.get("encryptedKey"));
                Assert.assertNotNull(encData.get("cipherData"));

            }
        }

        public Map<String, String> getHeaders()
        {
            return headers;
        }

        public Map<String, String> getData()
        {
            return data;
        }

        public SensitiveDataManager getManagerFromRawData()
        {
            return managerFromRawData;
        }

        public SensitiveDataManager getManagerFromEncryptedData()
        {
            return managerFromEncryptedData;
        }
    }

    /**
     * A TPM that connects the Microsoft TPM simulator on TCP port 2322.
     * The Simulator does not handle close and reconnect properly, this implementation works around that.
     */
    private static class TpmSimulator extends Tpm
    {
        private static final Object deviceSync = new Object();
        private final AtomicBoolean isOpen = new AtomicBoolean(true);
        private static TpmDevice tpmDevice;
        private static int openSimulators = 0;
        private static TpmDevice getTpmDevice()
        {
            synchronized (deviceSync)
            {
                if(tpmDevice == null)
                {
                    tpmDevice =TpmFactory.localTpmSimulator()._getDevice();
                }
                return tpmDevice;
            }
        }

        static void closeDevice()
        {
            synchronized (deviceSync)
            {
                if(tpmDevice != null)
                {
                    tpmDevice.close();
                }
            }
        }

        public TpmSimulator()
        {
            _setDevice(getTpmDevice());
            // Expect only one TPM instance at given any time.
            Assert.assertEquals(0, openSimulators);
            openSimulators++;
        }

        @Override
        protected void DispatchCommand(TPM_CC cmdCode, ReqStructure req, RespStructure resp)
        {
            if(!isOpen.get())
            {
                throw new LetsConfideException("TPM is closed");
            }
            super.DispatchCommand(cmdCode, req, resp);
        }

        @Override
        public void close()
        {
            isOpen.set(false);
            openSimulators--;
        }
    }

}
