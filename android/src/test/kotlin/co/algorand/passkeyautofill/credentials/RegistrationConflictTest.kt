package co.algorand.passkeyautofill.credentials

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RegistrationConflictTest {
    private val id = byteArrayOf(1, 2, 3)

    @Test
    fun allowsANewCredential() {
        assertFalse(RegistrationConflict.refuses(id, listOf(byteArrayOf(9)), storedLocally = false))
        assertFalse(RegistrationConflict.refuses(id, emptyList(), storedLocally = false))
    }

    @Test
    fun refusesAnExcludedCredential() {
        assertTrue(RegistrationConflict.refuses(id, listOf(byteArrayOf(9), byteArrayOf(1, 2, 3)), storedLocally = false))
    }

    @Test
    fun refusesACredentialAlreadyStored() {
        assertTrue(RegistrationConflict.refuses(id, emptyList(), storedLocally = true))
    }
}
