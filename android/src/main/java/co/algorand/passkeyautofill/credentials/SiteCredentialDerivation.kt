package co.algorand.passkeyautofill.credentials

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
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
 * This must match the iOS provider (CredentialProviderViewController.domainSpecificKeyPair
 * and ASPasskeyCredentialIdentity.userHandleString) byte for byte, so that a passkey created
 * through Akita on one platform can be re-derived on any other. The test vectors in
 * src/test come from running the iOS code.
 *
 *   handle = lowercase(utf8(user.id) ?: base64url(user.id))
 *   digest = SHA-512(root ‖ utf8(rpId) ‖ utf8(handle) ‖ BE32(attempt))
 *   d      = digest[0..32], for the first attempt in 0..15 where 1 ≤ d < n
 */
object SiteCredentialDerivation {
    private const val MAX_ATTEMPTS = 16
    private val CURVE = ECNamedCurveTable.getParameterSpec("secp256r1")
    private val UTF8_BOM = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte())

    /**
     * The derivation input for a site's WebAuthn user.id, matching iOS: the bytes as UTF-8
     * text when they are valid UTF-8 (Foundation drops a leading byte-order mark), otherwise
     * unpadded base64url. Lowercased one code point at a time, like Swift's
     * String.lowercased(), which applies no context rules such as Greek final sigma.
     */
    fun canonicalUserHandle(userId: ByteArray): String {
        val text = decodeUtf8OrNull(userId) ?: base64UrlNoPadding(userId)
        return lowercasePerCodePoint(text)
    }

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

    private fun decodeUtf8OrNull(bytes: ByteArray): String? {
        val body = if (bytes.size >= 3 && bytes.copyOfRange(0, 3).contentEquals(UTF8_BOM)) {
            bytes.copyOfRange(3, bytes.size)
        } else {
            bytes
        }
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        return try {
            decoder.decode(ByteBuffer.wrap(body)).toString()
        } catch (e: CharacterCodingException) {
            null
        }
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

    // java.util.Base64 needs API 26 and this module supports API 24.
    private const val BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    private fun base64UrlNoPadding(bytes: ByteArray): String {
        val out = StringBuilder((bytes.size * 4 + 2) / 3)
        var i = 0
        while (i < bytes.size) {
            val b0 = bytes[i].toInt() and 0xFF
            val b1 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xFF else -1
            val b2 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xFF else -1
            out.append(BASE64URL[b0 ushr 2])
            out.append(BASE64URL[((b0 and 0x03) shl 4) or (if (b1 >= 0) b1 ushr 4 else 0)])
            if (b1 >= 0) out.append(BASE64URL[((b1 and 0x0F) shl 2) or (if (b2 >= 0) b2 ushr 6 else 0)])
            if (b2 >= 0) out.append(BASE64URL[b2 and 0x3F])
            i += 3
        }
        return out.toString()
    }
}
