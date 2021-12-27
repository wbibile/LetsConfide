package org.letsconfide.platform;

import org.letsconfide.config.ConfigHeaders;

import java.util.List;
import java.util.Map.Entry;

/**
 * A factory responsible for manufacturing {@link SecurityDevice}s.
 */
public interface DeviceFactory
{
    /**
     * Creates a new device reconstituted from persistent device tokens.
     *
     * @param headers      Config headers
     * @param deviceTokens Persistent device tokens
     * @return the new device
     */
    SecurityDevice newDevice(ConfigHeaders headers, List<byte[]> deviceTokens);

    /**
     * Creates a new device and generates all associated persistent tokens.
     * The generated tokens can be used later to reconstitute device-state from storage.
     *
     * @param headers Config headers
     * @return An entry containing the new device and persistent state
     */
    Entry<SecurityDevice, List<byte[]>> newDevice(ConfigHeaders headers);
}
