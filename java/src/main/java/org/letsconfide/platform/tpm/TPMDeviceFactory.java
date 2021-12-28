package org.letsconfide.platform.tpm;

import org.letsconfide.config.ConfigHeaders;
import org.letsconfide.platform.DeviceFactory;
import org.letsconfide.platform.SecurityDevice;
import tss.Tpm;
import tss.TpmFactory;

import javax.annotation.CheckForNull;
import java.util.AbstractMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * Device factory that manufactures {@link TPMDevice}s.
 * Typically, this should be limited to one instance per application.
 */
public class TPMDeviceFactory implements DeviceFactory
{
    private final List<byte[]> ephemeralTokens = new CopyOnWriteArrayList<>();
    private final AtomicBoolean ephemeralTokensGenerated = new AtomicBoolean();
    // Context for synchronizing access to the TPM.
    private final Object tpmSync = new Object();

    /**
     * Platform device factory.
     */
    public static final DeviceFactory PLATFORM_INSTANCE =  new TPMDeviceFactory(TpmFactory::platformTpm);
    private final Supplier<Tpm> factory;

    /**
     * Constructs a TPM device factory.
     * Use {@link #PLATFORM_INSTANCE} to get the TPM platform TPM factory.
     * @param tpmFactory TSS TPM supplier
     */
    public TPMDeviceFactory(Supplier<Tpm> tpmFactory)
    {
        this.factory = tpmFactory;
    }

    /**
     * Used by unit tests to reset state (unnecessary in production).
     */
    public void reset()
    {
        ephemeralTokensGenerated.set(false);
        ephemeralTokens.clear();
    }

    @Override
    public SecurityDevice newDevice(ConfigHeaders headers, List<byte[]> deviceTokens)
    {
        return newDevice(headers, deviceTokens, ephemeralTokens);
    }

    @Override
    public Map.Entry<SecurityDevice, List<byte[]>> newDevice(ConfigHeaders headers)
    {
        TPMDevice result = newDevice(headers, null, null);
        return new AbstractMap.SimpleEntry<>(result, result.getDeviceTokens());
    }

    private TPMDevice newDevice(ConfigHeaders headers, @CheckForNull List<byte[]> deviceTokens, @CheckForNull List<byte[]> ephemeralTokens)
    {
        synchronized (tpmSync)
        {
            TPMDevice result;
            if (ephemeralTokensGenerated.compareAndSet(false, true))
            {
                assert ephemeralTokens == null || ephemeralTokens.isEmpty();
                result = new TPMDevice(factory.get(), tpmSync, headers, deviceTokens, null);
                this.ephemeralTokens.addAll(result.getEphemeralTokens());
            }
            else
            {
                result = new TPMDevice(factory.get(), tpmSync, headers, deviceTokens, ephemeralTokens);
            }
            return result;
        }
    }


}
