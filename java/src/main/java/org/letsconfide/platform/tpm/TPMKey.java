package org.letsconfide.platform.tpm;

import tss.Tpm;
import tss.tpm.TPM_HANDLE;

/**
 * Base class for keys that are based on a TPM.
 */
public abstract class TPMKey
{
    private final Tpm tpm;

    /**
     * @param tpm The TPM
     */
    TPMKey(Tpm tpm)
    {
        this.tpm = tpm;
    }

    /**
     * @return The TPM
     */
    public Tpm getTpm()
    {
        return tpm;
    }

    /**
     * @return The TPM handle associated with this key
     */
    public abstract TPM_HANDLE getKeyHandle();


}
