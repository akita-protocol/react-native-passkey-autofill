package co.algorand.passkeyautofill.credentials

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TransactionPreviewPolicyTest {
    @Test
    fun mapsTheNativeTriple() {
        assertEquals(TransactionPreviewPolicy.Never, TransactionPreviewPolicy.fromNativeConfiguration(false, "", ""))
        assertEquals(
            TransactionPreviewPolicy.Required("https://preview.akita.example", "preview-token"),
            TransactionPreviewPolicy.fromNativeConfiguration(true, "https://preview.akita.example", "preview-token"),
        )
    }

    @Test
    fun refusesStaleConfigurationOnNever() {
        assertThrows(IllegalArgumentException::class.java) {
            TransactionPreviewPolicy.fromNativeConfiguration(false, "https://preview.akita.example", "")
        }
        assertThrows(IllegalArgumentException::class.java) {
            TransactionPreviewPolicy.fromNativeConfiguration(false, "", "stale-token")
        }
    }

    @Test
    fun refusesEndpointsThatAreNotExactHttpsOrigins() {
        for (endpoint in listOf(
            "http://preview.akita.example",
            "https://preview.akita.example/",
            "https://preview.akita.example/v1",
            "https://preview.akita.example?tenant=akita",
            "https://preview.akita.example#preview",
            "https://preview.akita.example\\v1",
            "https:preview.akita.example",
            "https://@preview.akita.example",
            " https://preview.akita.example",
            "https://preview.akita.example:99999",
        )) {
            assertThrows(endpoint, IllegalArgumentException::class.java) {
                TransactionPreviewPolicy.fromNativeConfiguration(true, endpoint, "preview-token")
            }
        }
    }

    @Test
    fun refusesEmptyOrPaddedTokens() {
        for (token in listOf("", " token", "token\n")) {
            assertThrows(IllegalArgumentException::class.java) {
                TransactionPreviewPolicy.fromNativeConfiguration(true, "https://preview.akita.example", token)
            }
        }
    }

    @Test
    fun readsRestoreRecords() {
        assertEquals(TransactionPreviewPolicy.Never, TransactionPreviewPolicy.fromRestoreRecord(emptyMap()))
        assertEquals(
            TransactionPreviewPolicy.Never,
            TransactionPreviewPolicy.fromRestoreRecord(mapOf("showTransactionRequests" to false)),
        )
        assertEquals(
            TransactionPreviewPolicy.Required("https://preview.akita.example", "t"),
            TransactionPreviewPolicy.fromRestoreRecord(
                mapOf(
                    "transactionPreviewPolicy" to mapOf(
                        "kind" to "required",
                        "httpsEndpoint" to "https://preview.akita.example",
                        "token" to "t",
                    ),
                ),
            ),
        )
        assertThrows(IllegalArgumentException::class.java) {
            TransactionPreviewPolicy.fromRestoreRecord(
                mapOf("showTransactionRequests" to true, "previewApiBaseUrl" to "https://preview.akita.example"),
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            TransactionPreviewPolicy.fromRestoreRecord(
                mapOf(
                    "transactionPreviewPolicy" to mapOf("kind" to "never"),
                    "showTransactionRequests" to false,
                ),
            )
        }
    }
}
