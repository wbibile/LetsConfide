package org.letsconfide.platform.tpm;

import org.letsconfide.config.ConfigHeaders;
import org.letsconfide.platform.DeviceFactory;
import org.letsconfide.platform.SecurityDevice;
import tss.Tpm;

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
    private final Tpm tpm;

    /**
     *
     * @param tpmFactory TSS TPM supplier
     */
    public TPMDeviceFactory(Supplier<Tpm> tpmFactory)
    {
        this.tpm = tpmFactory.get();
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

    private TPMDevice newDevice(ConfigHeaders headers, @CheckForNull List<byte[]> deviceTokens,@CheckForNull List<byte[]> ephemeralTokens)
    {
        synchronized (tpm)
        {
            TPMDevice result;
            if (ephemeralTokensGenerated.compareAndSet(false, true))
            {
                assert ephemeralTokens == null || ephemeralTokens.isEmpty();
                result = new TPMDevice(tpm, headers, deviceTokens, null);
                this.ephemeralTokens.addAll(result.getEphemeralTokens());
            }
            else
            {
                result = new TPMDevice(tpm, headers, deviceTokens, ephemeralTokens);
            }
            return result;
        }
    }

}
