package org.letsconfide.platform.tpm;

import tss.tpm.TPM_HANDLE;

import java.util.List;

/**
 * Represents a Key encryption Key on the TPM.
 */
public interface TpmKeyEncryptionKey
{
    /**
     * Wraps a data encryption key
     * @param dek the data encryption key bytes
     * @return wrapped (encrypted) data encryption key
     */
    byte[] wrap(byte[] dek);

    /**
     * Unwraps an encrypted data encryption key.
     * This function is the inverse of {@link #wrap(byte[])}.
     * @param encryptedDek Encrypted data encryption key
     * @return unwrapped data encryption key
     */
    byte[] unwrap(byte[] encryptedDek);

    /**
     * Tokens associated with this key.
     * These tokens can be used to reconstitute the key at a later time.
     * @return List of tokens
     */
    List<byte[]> getTokens();

    /**
     * @return The TPM handle associated with this key
     */
    TPM_HANDLE getKeyHandle();

}
