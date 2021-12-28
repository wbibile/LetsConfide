package org.letsconfide.config;

import org.junit.Assert;
import org.junit.Test;
import org.letsconfide.LetsConfideException;
import org.letsconfide.SensitiveDataManager;
import org.letsconfide.Utils;
import org.letsconfide.platform.FakeDeviceFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.letsconfide.config.ConfigHeaders.DEFAULT;

public class ConfigParserTest
{

    @Test
    public void testEmptyYamlFile() throws Exception
    {
        Path yamlFile = Files.createTempFile("testYaml", ".yaml");
        try
        {
            new ConfigParser().parse(yamlFile.toFile(), new FakeDeviceFactory());
            Assert.fail("Expect parse failure because the file is empty ");
        }
        catch (LetsConfideException e)
        {
            Assert.assertEquals("Error parsing YAML file: Unexpected entry at line 0", e.getMessage());
        }
    }

    @Test
    public void testDuplicateHeader() throws IOException
    {
        Map<String, Object> root = new LinkedHashMap<>();
        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put("primaryKeyType", "AES256");
        headers.put("storageKeyType", "AES256");
        // Add a marker for the duplicate header.
        headers.put("storageKeyType2","AES256");
        headers.put("pcrSelection", "1");
        headers.put("pcrHash", "SHA256");
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("my_passwd", "ub,KbVsh/XUj~=~F#");

        root.put("headers", headers);
        root.put("data", data);

        String yamlStr = Utils.newYamlInstance().dump(root);
        // Replace the marker with the duplicate.
        yamlStr = yamlStr.replace("storageKeyType2", "storageKeyType");
        Path yamlFile = Files.createTempFile("testYaml", ".yaml");
        Files.write(yamlFile, yamlStr.getBytes(StandardCharsets.UTF_8), WRITE, TRUNCATE_EXISTING);

        try
        {
            new ConfigParser().parse(yamlFile.toFile(), new FakeDeviceFactory());
            Assert.fail("Duplicate header must cause a failure.");
        }
        catch (LetsConfideException e)
        {
            Assert.assertEquals("Error parsing YAML file: Duplicate key at line 3", e.getMessage());
        }
    }

    @Test
    public void testInvalidHeader() throws Exception
    {
        Map<String, Object> root = new LinkedHashMap<>();
        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put("primaryKeyType", "AES256");
        headers.put("storageKeyType", "AES256");
        // Add the invalid header.
        headers.put("storageKeyType2","AES256");
        headers.put("pcrSelection", "1");
        headers.put("pcrHash", "SHA256");
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("my_passwd", "ub,KbVsh/XUj~=~F#");

        root.put("headers", headers);
        root.put("data", data);

        Path yamlFile = Files.createTempFile("testYaml", ".yaml");
        Utils.writeToYamlFile(root, yamlFile);
        try
        {
            new ConfigParser().parse(yamlFile.toFile(), new FakeDeviceFactory());
            Assert.fail("Invalid header storageKeyType2 must cause a failure.");
        }
        catch (LetsConfideException e)
        {
            Assert.assertEquals("Error parsing YAML file: Invalid config header at line 3", e.getMessage());
        }
    }

    @Test
    public void testDuplicateData() throws IOException
    {
        Map<String, Object> root = new LinkedHashMap<>();
        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put("primaryKeyType", "AES256");
        headers.put("storageKeyType", "AES256");
        headers.put("pcrSelection", "1");
        headers.put("pcrHash", "SHA256");
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("my_passwd", "ub,KbVsh/XUj~=~F#");
        data.put("my_passwd2", "ub,KbVsh/XUj~=~F#");
        root.put("headers", headers);
        root.put("data", data);

        String yamlStr = Utils.newYamlInstance().dump(root);
        yamlStr = yamlStr.replace("my_passwd2", "my_passwd");
        Path yamlFile = Files.createTempFile("testYaml", ".yaml");
        Files.write(yamlFile, yamlStr.getBytes(StandardCharsets.UTF_8), WRITE, TRUNCATE_EXISTING);

        try
        {
            new ConfigParser().parse(yamlFile.toFile(), new FakeDeviceFactory());
            Assert.fail("Duplicate header must cause a failure.");
        }
        catch (LetsConfideException e)
        {
            Assert.assertEquals("Error parsing YAML file: Duplicate key at line 7", e.getMessage());
        }

    }

    @Test
     public void testDefaults() throws Exception
     {
         Map<String, Object> root = new LinkedHashMap<>();

         Map<String, Object> data = new LinkedHashMap<>();
         data.put("pwd1", "ub,KbVsh/XUj~=~F#");
         root.put("data", data);
         Path yamlFile = Files.createTempFile("testYaml", ".yaml");
         Utils.writeToYamlFile(root, yamlFile);
         SensitiveDataManager manager = new ConfigParser().parse(yamlFile.toFile(), new FakeDeviceFactory());

         try(SensitiveDataManager.DataAccessSession session = manager.startDataAccessSession())
         {
             // Check data
             Assert.assertArrayEquals("ub,KbVsh/XUj~=~F#".toCharArray(), session.decrypt("pwd1"));
         }
         // Check default headers.
         Assert.assertEquals(DEFAULT, manager.getHeaders());
     }

    @Test
    public void testPartialDefaults() throws Exception
    {
        assertPartialDefaults("primaryKeyType",DEFAULT.getPrimaryKeyType());
        assertPartialDefaults("storageKeyType", DEFAULT.getStorageKeyType());
        assertPartialDefaults("pcrSelection", DEFAULT.getPcrSelection());
        assertPartialDefaults("pcrHash", DEFAULT.getPcrHash());
    }

    public void assertPartialDefaults(String missingHeader, Object expectedDefault) throws Exception
    {
        Map<String, Object> root = new LinkedHashMap<>();
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("primaryKeyType", "RSA2048");
        headers.put("storageKeyType", "AES128");
        headers.put("pcrSelection", "2");
        headers.put("pcrHash", "SHA1");
        headers.remove(missingHeader);

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("pwd1", "ub,KbVsh/XUj~=~F#");
        root.put("headers", headers);
        root.put("data", data);
        Path yamlFile = Files.createTempFile("testYaml", ".yaml");
        Utils.writeToYamlFile(root, yamlFile);
        ConfigHeaders configHeaders = new ConfigParser().parse(yamlFile.toFile(), new FakeDeviceFactory()).getHeaders();

        Object actual = null;
        switch (missingHeader)
        {
            case "primaryKeyType":
                actual = configHeaders.getPrimaryKeyType();
                break;
            case "storageKeyType":
                actual = configHeaders.getStorageKeyType();
                break;
            case "pcrSelection":
                actual = configHeaders.getPcrSelection();
                break;
            case "pcrHash":
                actual = configHeaders.getPcrHash();
                break;
            default:
                Assert.fail("Unknown header "+missingHeader);
        }
        // Check default headers.
        Assert.assertEquals(expectedDefault, actual);
    }

    @Test
    public void testMissingDataElements() throws Exception
    {
        Map<String, Object> root = new LinkedHashMap<>();
        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put("primaryKeyType", "AES256");
        headers.put("storageKeyType", "AES256");
        headers.put("pcrSelection", "1");
        headers.put("pcrHash", "SHA256");
        root.put("headers",  headers);

        root.put("data",  "foobar");
        Path yamlFile = Files.createTempFile("testYaml", ".yaml");
        Utils.writeToYamlFile(root, yamlFile);

        try
        {
            //noinspection ResultOfMethodCallIgnored
            new ConfigParser().parse(yamlFile.toFile(), new FakeDeviceFactory()).getHeaders();
            Assert.fail("Expect failure when there are no data entries.");
        }
        catch (LetsConfideException e)
        {
            Assert.assertEquals("Error parsing YAML file: Unexpected entry at line 5", e.getMessage());
        }
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    @Test
    public void testMissingData() throws Exception
    {
        Map<String, Object> root = new LinkedHashMap<>();
        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put("primaryKeyType", "AES256");
        headers.put("storageKeyType", "AES256");
        headers.put("pcrSelection", "1");
        headers.put("pcrHash", "SHA256");
        root.put("headers",  headers);
        // No data entry in the YAML file.

        Path yamlFile = Files.createTempFile("testYaml", ".yaml");
        Utils.writeToYamlFile(root, yamlFile);

        try
        {
            new ConfigParser().parse(yamlFile.toFile(), new FakeDeviceFactory()).getHeaders();
            Assert.fail("Missing data");
        }
        catch (LetsConfideException e)
        {
            Assert.assertEquals("Error parsing YAML file: Unexpected entry at line 5", e.getMessage());
        }

    }

}
