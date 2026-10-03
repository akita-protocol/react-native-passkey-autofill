package co.algorand.passkeyautofill.credentials

import java.net.URI
import java.net.URISyntaxException

/**
 * Akita: whether a passkey's assertions must first show the user a native
 * transaction preview. Closed — exactly [Never] or a complete [Required] — and
 * validated the same way as the iOS provider (TransactionPreviewPolicy.swift) and
 * the JS `mapTransactionPreviewPolicyToNative`, so a partial or contradictory
 * configuration is refused instead of being read as "no preview".
 */
sealed class TransactionPreviewPolicy {
    object Never : TransactionPreviewPolicy()

    /** [httpsEndpoint] is exactly an HTTPS origin; [token] is the bearer token. */
    data class Required(val httpsEndpoint: String, val token: String) : TransactionPreviewPolicy()

    /** The JS shape: `{kind: "never"}` or `{kind: "required", httpsEndpoint, token}`. */
    fun toMap(): Map<String, String> = when (this) {
        is Never -> mapOf("kind" to "never")
        is Required -> mapOf("kind" to "required", "httpsEndpoint" to httpsEndpoint, "token" to token)
    }

    companion object {
        /**
         * Maps the native bridge's `(required, endpoint, token)` triple. `false`
         * must come with an empty endpoint and token; `true` with a valid pair.
         */
        fun fromNativeConfiguration(required: Boolean, httpsEndpoint: String, token: String): TransactionPreviewPolicy {
            if (!required) {
                require(httpsEndpoint.isEmpty() && token.isEmpty()) {
                    "Disabled transaction preview cannot include an endpoint or token."
                }
                return Never
            }
            return validatedRequired(httpsEndpoint, token)
        }

        /** The policy of a restored record: `{kind, …}` map, or the legacy flat fields. */
        fun fromRestoreRecord(record: Map<String, Any?>): TransactionPreviewPolicy {
            val hasLegacy = LEGACY_KEYS.any { record.containsKey(it) }
            val canonical = record["transactionPreviewPolicy"]
            if (canonical != null) {
                require(!hasLegacy) { "Transaction preview policy given twice." }
                val map = canonical as? Map<*, *> ?: throw IllegalArgumentException("Malformed transaction preview policy.")
                return when (map["kind"]) {
                    "never" -> {
                        require(!map.containsKey("httpsEndpoint") && !map.containsKey("token")) {
                            "Disabled transaction preview cannot include an endpoint or token."
                        }
                        Never
                    }
                    "required" -> validatedRequired(
                        map["httpsEndpoint"] as? String ?: throw IllegalArgumentException("Missing preview endpoint."),
                        map["token"] as? String ?: throw IllegalArgumentException("Missing preview token."),
                    )
                    else -> throw IllegalArgumentException("Malformed transaction preview policy.")
                }
            }
            if (!hasLegacy) return Never
            val required = record["showTransactionRequests"] as? Boolean
                ?: throw IllegalArgumentException("Incomplete legacy transaction preview policy.")
            val endpoint = record["previewApiBaseUrl"]
            val token = record["previewToken"]
            if (!required) {
                require(endpoint == null && token == null) { "Incomplete legacy transaction preview policy." }
                return Never
            }
            return validatedRequired(
                endpoint as? String ?: throw IllegalArgumentException("Incomplete legacy transaction preview policy."),
                token as? String ?: throw IllegalArgumentException("Incomplete legacy transaction preview policy."),
            )
        }

        fun validatedRequired(httpsEndpoint: String, token: String): Required {
            require(isHttpsOrigin(httpsEndpoint)) { "Transaction preview requires a valid HTTPS endpoint." }
            require(token.isNotEmpty() && token.trim() == token) { "Transaction preview requires a non-empty token." }
            return Required(httpsEndpoint, token)
        }

        private val LEGACY_KEYS = listOf("showTransactionRequests", "previewApiBaseUrl", "previewToken")

        private fun isHttpsOrigin(endpoint: String): Boolean {
            if (endpoint.trim() != endpoint || !endpoint.startsWith("https://", ignoreCase = true)) return false
            val authority = endpoint.substring("https://".length)
            if (authority.isEmpty() || authority.any { it.code <= 0x20 || it.code == 0x7f || it in "\\/?#@" }) {
                return false
            }
            val uri = try {
                URI(endpoint)
            } catch (e: URISyntaxException) {
                return false
            }
            return uri.scheme.equals("https", ignoreCase = true) &&
                !uri.host.isNullOrEmpty() &&
                uri.rawUserInfo == null &&
                uri.rawPath.isNullOrEmpty() &&
                uri.rawQuery == null &&
                uri.rawFragment == null &&
                uri.port in -1..65535
        }
    }
}
