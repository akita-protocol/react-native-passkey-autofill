package co.algorand.passkeyautofill.credentials

/**
 * Akita: passkey keys are derived deterministically, so registering the same
 * account again produces the same credential id. Such a registration must fail
 * (WebAuthn InvalidStateError) instead of overwriting the stored passkey — and
 * with it the transaction-preview policy configured for it.
 */
object RegistrationConflict {
    /**
     * Whether creating `credentialId` must be refused: the relying party listed it
     * in `excludeCredentials`, or a record for it is already stored on this device.
     */
    fun refuses(credentialId: ByteArray, excludedIds: List<ByteArray>, storedLocally: Boolean): Boolean =
        storedLocally || excludedIds.any { it.contentEquals(credentialId) }
}
