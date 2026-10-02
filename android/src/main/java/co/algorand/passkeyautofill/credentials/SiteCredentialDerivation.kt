package co.algorand.passkeyautofill.credentials

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.util.Locale
import org.bouncycastle.jce.ECNamedCurveTable

/**
 * Derives the P-256 key for a site passkey from the wallet's HD root secret.
 *
 * This must match the iOS provider (SiteCredentialDerivation in
 * PasskeyCredentialStore.swift) byte for byte, so a passkey created through Akita
 * on one platform can be re-derived on any other. The test vectors in src/test
 * come from running the iOS code.
 *
 *   handle = lowercase(user.name), one code point at a time
 *   digest = SHA-512(root ‖ utf8(rpId) ‖ utf8(handle) ‖ BE32(attempt))
 *   d      = digest[0..32], for the first attempt in 0..15 where 1 ≤ d < n
 *
 * user.name (rather than the opaque user.id) is deliberate: it is something a
 * person can supply again during recovery.
 */
object SiteCredentialDerivation {
    private const val MAX_ATTEMPTS = 16
    private val CURVE = ECNamedCurveTable.getParameterSpec("secp256r1")

    /**
     * The derivation input for a site's WebAuthn user.name. Lowercased one code
     * point at a time, like Swift's String.lowercased(): Kotlin's String.lowercase()
     * applies the Greek final-sigma context rule (and differs from ICU on it), so
     * it would not match iOS.
     */
    fun handleForUserName(userName: String): String = lowercasePerCodePoint(userName)

    /** Returns the private scalar and the attempt counter that produced it. */
    fun derivePrivateScalar(rootSecret: ByteArray, rpId: String, userHandle: String): Pair<BigInteger, Int> {
        val prefix = rootSecret + rpId.toByteArray(Charsets.UTF_8) + userHandle.toByteArray(Charsets.UTF_8)
        for (attempt in 0 until MAX_ATTEMPTS) {
            val counter = ByteBuffer.allocate(4).putInt(attempt).array()
            val digest = MessageDigest.getInstance("SHA-512").digest(prefix + counter)
            val d = BigInteger(1, digest.copyOfRange(0, 32))
            if (d.signum() > 0 && d < CURVE.n) return d to attempt
        }
        throw IllegalStateException("No valid P-256 key for this site after $MAX_ATTEMPTS attempts")
    }

    fun deriveKeyPair(rootSecret: ByteArray, rpId: String, userHandle: String): KeyPair {
        val (d, _) = derivePrivateScalar(rootSecret, rpId, userHandle)
        val q = CURVE.g.multiply(d).normalize()
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val keyFactory = KeyFactory.getInstance("EC")
        val publicKey = keyFactory.generatePublic(
            ECPublicKeySpec(ECPoint(q.affineXCoord.toBigInteger(), q.affineYCoord.toBigInteger()), params),
        )
        val privateKey = keyFactory.generatePrivate(ECPrivateKeySpec(d, params))
        return KeyPair(publicKey, privateKey)
    }

    private fun lowercasePerCodePoint(text: String): String {
        val out = StringBuilder(text.length)
        var i = 0
        while (i < text.length) {
            val codePoint = text.codePointAt(i)
            // A single code point has no neighbours, so context rules never apply.
            out.append(String(Character.toChars(codePoint)).lowercase(Locale.ROOT))
            i += Character.charCount(codePoint)
        }
        return out.toString()
    }
}
