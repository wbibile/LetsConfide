package org.letsconfide.platform.tpm;

import org.letsconfide.LetsConfideCloseable;
import org.letsconfide.LetsConfideException;
import org.letsconfide.config.ConfigHeaders;
import tss.Tpm;
import tss.tpm.*;

/**
 * Facilitates code to execution using a PCR policy session.<BR>
 * This class is typically used tp generate PCR policy sessions in-order to authenticate
 * storage keys against the values in the PCR registers.
 */
class WithPcrPolicySession implements LetsConfideCloseable
{
    private final TPM_HANDLE sessionHandle;
    private final ConfigHeaders headers;
    private final Tpm tpm;

    /**
     * Instantiates a session within the TPM.
     * Not this method does not attach the PCR policy.
     * @param tpm the TPM
     */
    WithPcrPolicySession(Tpm tpm, ConfigHeaders headers)
    {
        // It  may not be important for nonceCaller to be truly random, as NonceCaller becomes important only when using a
        // session sequentially with multiple commands (which doesn't appear to be supported by the TSS library).
        //1) In call to WriteSession() in tss.TpmBase.DispatchCommand() NonceCaller is null
        //2) tss.TpmBase.processRespSessions() is not implemented, which should be responsible for extracting the NonceTPM
        byte[] initialNonceCaller = TpmUtils.randomBytes(tpm, 16);
        StartAuthSessionResponse response = tpm.StartAuthSession(
                /*salt decryption key: not a salted session*/TPM_HANDLE.NULL,
                /*bindKey: not a bound session*/TPM_HANDLE.NULL,
                /*NonceCaller*/ initialNonceCaller,
                /*encrypted salt: This is not a salted session*/ new byte[0],
                /*Session type*/TPM_SE.POLICY,
                /*Not used for parameter encryption*/new TPMT_SYM_DEF(TPM_ALG_ID.NULL, 0, TPM_ALG_ID.NULL),
                /*Hash used for HMAC auth although not supported by current TSS*/TPM_ALG_ID.SHA256);
        sessionHandle = response.handle;
        this.tpm = tpm;
        this.headers = headers;
    }

    /**
     * Initializes the PCR policy.
     */
    void initPcrPolicy()
    {
        TPMS_PCR_SELECTION[] pcrSel = TpmUtils.getPcrSelection(headers);
        tpm.PolicyPCR(sessionHandle,
                /*PCR digest: The empty digest indicates that the TPM should calculate the digest */
                new byte[0],
                // PCR selection
                pcrSel);
    }

    /**
     * @return The TPM session handle
     */
    TPM_HANDLE getSessionHandle()
    {
        return sessionHandle;
    }

    @Override
    public void close() throws LetsConfideException
    {
        tpm.FlushContext(sessionHandle);
    }
}
