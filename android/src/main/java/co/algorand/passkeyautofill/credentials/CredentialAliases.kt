package co.algorand.passkeyautofill.credentials

import java.util.Base64

/**
 * Akita: one credential id can be stored under several keys — standard or
 * URL-safe base64, as a sealed flat record or a plaintext `k/` metadata record.
 * Every read and write resolves ALL of them, and copies that disagree on the
 * transaction-preview policy quarantine the credential (it is not offered, read
 * or signed with) instead of one copy winning by lookup order. Mirrors
 * `resolveTransactionPreviewAuthority` in the iOS provider.
 */
object CredentialAliases {
    /** The id's bytes from standard or URL-safe base64, padded or not. */
    fun decode(id: String): ByteArray? {
        val normalized = id.trim().replace('-', '+').replace('_', '/').trimEnd('=')
        if (normalized.isEmpty()) return null
        val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
        return try {
            Base64.getDecoder().decode(padded)
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    /** Every storage key spelling of these id bytes. */
    fun candidates(id: ByteArray): Set<String> = linkedSetOf(
        Base64.getEncoder().encodeToString(id),
        Base64.getUrlEncoder().withoutPadding().encodeToString(id),
    )

    /** Every storage key spelling of `id`, including `id` as given. */
    fun candidates(id: String): Set<String> {
        val result = linkedSetOf(id.trim())
        decode(id)?.let { result.addAll(candidates(it)) }
        return result
    }

    /** One spelling per credential: unpadded URL-safe base64 of its bytes. */
    fun canonical(id: String): String =
        decode(id)?.let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) } ?: id.trim()

    /** What two copies of one credential must agree on. */
    fun policyKey(credential: Credential): Triple<Boolean, String?, String?> =
        if (credential.showTransactionRequests) {
            Triple(true, credential.previewApiBaseUrl, credential.previewToken)
        } else {
            Triple(false, null, null)
        }

    /** The credential its copies describe, or `null` when there are none or they disagree. */
    fun resolve(copies: List<Credential>): Credential? {
        val first = copies.firstOrNull() ?: return null
        val key = policyKey(first)
        return if (copies.all { policyKey(it) == key }) first else null
    }

    /** Enumeration: one entry per credential; credentials whose copies disagree are left out. */
    fun quarantine(credentials: List<Credential>): List<Credential> =
        credentials.groupBy { canonical(it.credentialId) }.values.mapNotNull { resolve(it) }
}
