package co.algorand.passkeyautofill.credentials

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialAliasesTest {
    // 0xfb 0xff: "+/8=" in standard base64, "-_8" URL-safe.
    private val bytes = byteArrayOf(0xfb.toByte(), 0xff.toByte())

    private fun credential(
        id: String,
        required: Boolean = false,
        endpoint: String? = null,
        token: String? = null,
    ) = Credential(
        credentialId = id,
        origin = "example.com",
        userHandle = "alice",
        userId = "dXNlcg",
        publicKey = "",
        privateKey = "",
        count = 0,
        showTransactionRequests = required,
        previewApiBaseUrl = endpoint,
        previewToken = token,
    )

    private val required = { id: String -> credential(id, true, "https://preview.akita.example", "t") }

    @Test
    fun resolvesEverySpellingOfAnId() {
        assertEquals(setOf("+/8=", "-_8"), CredentialAliases.candidates(bytes))
        assertTrue(CredentialAliases.candidates("-_8").containsAll(listOf("+/8=", "-_8")))
        assertTrue(CredentialAliases.candidates("+/8=").containsAll(listOf("+/8=", "-_8")))
        assertArrayEquals(bytes, CredentialAliases.decode("-_8"))
        assertArrayEquals(bytes, CredentialAliases.decode("+/8"))
        assertEquals(CredentialAliases.canonical("+/8="), CredentialAliases.canonical("-_8"))
    }

    @Test
    fun agreeingCopiesResolve() {
        assertEquals("+/8=", CredentialAliases.resolve(listOf(required("+/8="), required("-_8")))?.credentialId)
        // A disabled flag with a stale endpoint is still "never".
        assertEquals(
            "+/8=",
            CredentialAliases.resolve(listOf(credential("+/8="), credential("-_8", false, "https://x.example", null)))
                ?.credentialId,
        )
    }

    @Test
    fun disagreeingCopiesAreRefused() {
        // The fail-open case: a never-policy copy under the URL-safe spelling must
        // not let a required-policy credential sign without a preview.
        assertNull(CredentialAliases.resolve(listOf(required("+/8="), credential("-_8"))))
        assertNull(
            CredentialAliases.resolve(
                listOf(required("+/8="), credential("-_8", true, "https://other.example", "t")),
            ),
        )
        assertNull(CredentialAliases.resolve(emptyList()))
    }

    @Test
    fun enumerationQuarantinesDisagreeingCredentials() {
        val listed = CredentialAliases.quarantine(
            listOf(required("+/8="), credential("-_8"), credential("AQ=="), credential("AQ")),
        )
        assertEquals(listOf("AQ=="), listed.map { it.credentialId })
    }
}
