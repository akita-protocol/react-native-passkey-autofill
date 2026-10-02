package co.algorand.passkeyautofill

import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.graphics.Color
import android.graphics.Typeface
import android.view.Gravity
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.credentials.webauthn.AuthenticatorAssertionResponse
import androidx.credentials.webauthn.FidoPublicKeyCredential
import androidx.credentials.webauthn.PublicKeyCredentialRequestOptions
import co.algorand.passkeyautofill.credentials.CredentialRepository
import co.algorand.passkeyautofill.credentials.Credential
import co.algorand.passkeyautofill.utils.PasskeyUtils
import java.security.KeyPair
import java.security.MessageDigest
import java.net.HttpURLConnection
import java.net.URL
import android.util.Base64 as AndroidBase64
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class GetPasskeyActivity : AppCompatActivity() {
    private val credentialRepository = CredentialRepository()

    companion object {
        const val TAG = "GetPasskeyActivity"
    }

    private var origin: String = "unknown-origin"
    private var displayOrigin: String = "unknown-origin"
    private var userHandle: String = "unknown-user"
    private var credentialIdEnc: String? = null
    private var userVerification: String = "preferred"
    private var bundleRequestJson: String? = null
    private var request: ProviderGetCredentialRequest? = null
    private var biometricPromptResult: Any? = null
    private var systemUnlockedCipher: javax.crypto.Cipher? = null
    private var isHandling: Boolean = false
    private var hasApprovedTransactionPreview: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.i(TAG, "onCreate started")
        
        request = try {
            PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        } catch (e: Exception) {
            Log.e(TAG, "Error retrieving request from intent", e)
            null
        }
        Log.i(TAG, "Retrieved request: $request")
        
        // Check for system-provided biometric result (Single Tap flow)
        try {
            val biometricResult = request?.biometricPromptResult
            Log.i(TAG, "biometricResult from system: $biometricResult")
            if (biometricResult != null) {
                this.biometricPromptResult = biometricResult
                val authResult = biometricResult.authenticationResult
                Log.i(TAG, "authResult from system: $authResult (${authResult?.javaClass?.name})")
                
                // Also try to find it in the biometricResult object itself
                systemUnlockedCipher = if (authResult != null) {
                    PasskeyUtils.extractCipher(authResult)
                } else {
                    PasskeyUtils.extractCipher(biometricResult)
                }
                Log.i(TAG, "systemUnlockedCipher from system: $systemUnlockedCipher")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing biometricPromptResult", e)
        }

        val credentialData = intent.getBundleExtra("CREDENTIAL_DATA")

        if (credentialData != null) {
            credentialIdEnc = credentialData.getString("credentialId")
            userHandle = credentialData.getString("userHandle") ?: "unknown-user"
            bundleRequestJson = credentialData.getString("requestJson")
            userVerification = credentialData.getString("userVerification") ?: "preferred"
        }

        if (request != null) {
            origin = credentialRepository.getOrigin(request!!.callingAppInfo)
            displayOrigin = origin
            
            // Try to extract rpId for better display
            val rawJson = bundleRequestJson ?: (request?.credentialOptions?.get(0) as? GetPublicKeyCredentialOption)?.requestJson
            if (rawJson != null) {
                try {
                    val jsonObj = JSONObject(rawJson)
                    val pkJson = if (jsonObj.has("publicKey")) jsonObj.getJSONObject("publicKey") else jsonObj
                    val rpId = pkJson.optString("rpId")
                    if (rpId.isNotEmpty()) {
                        displayOrigin = rpId
                    }
                } catch (e: Exception) {
                    // ignore
                }
            }
        }

        // If the system already showed a biometric prompt (Single Tap), proceed automatically
        if (biometricPromptResult != null) {
            Log.d(TAG, "System already showed biometric prompt (Single Tap), proceeding automatically")
            beginAssertionFlow()
            return
        }

        // Auto-trigger assertion flow
        beginAssertionFlow()
    }

    private fun beginAssertionFlow() {
        if (isHandling) return
        lifecycleScope.launch {
            try {
                val credential = findStoredCredential()
                if (credential?.showTransactionRequests == true && !hasApprovedTransactionPreview) {
                    setupPreviewLoadingUI()
                    val preview = withContext(Dispatchers.IO) {
                        fetchAndValidateTransactionPreview(credential)
                    }
                    val approved = confirmTransactionPreview(preview)
                    if (!approved) {
                        setResult(RESULT_CANCELED)
                        finish()
                        return@launch
                    }
                    hasApprovedTransactionPreview = true
                }
                handleAssertion()
            } catch (error: Exception) {
                Log.e(TAG, "Required transaction preview failed", error)
                showPreviewFailure(error.message ?: "The required transaction preview could not be verified.")
            }
        }
    }

    private fun findStoredCredential(): Credential? {
        val requestedId = credentialIdEnc ?: return null
        val normalized = PasskeyUtils.normalizeBase64(requestedId)
        return credentialRepository.getAllCredentials(this).firstOrNull {
            PasskeyUtils.normalizeBase64(it.credentialId) == normalized
        }
    }

    private fun fetchAndValidateTransactionPreview(credential: Credential): TransactionPreview {
        val apiBaseUrl = credential.previewApiBaseUrl
            ?: throw IllegalStateException("Transaction preview is required but is not configured.")
        val token = credential.previewToken
            ?: throw IllegalStateException("Transaction preview is required but is not configured.")
        val base = URL(apiBaseUrl)
        if (base.protocol.lowercase() != "https") {
            throw IllegalStateException("Transaction preview endpoint must use HTTPS.")
        }
        val credentialIdBytes = AndroidBase64.decode(credential.credentialId, AndroidBase64.DEFAULT)
        val credentialId = AndroidBase64.encodeToString(
            credentialIdBytes,
            AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING
        )
        val endpoint = URL(base, "/akita/passkey-previews/$credentialId")
        val connection = endpoint.openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "GET"
            connection.connectTimeout = 10_000
            connection.readTimeout = 15_000
            connection.setRequestProperty("Authorization", "Bearer $token")
            connection.setRequestProperty("Accept", "application/json")
            if (connection.responseCode !in 200..299) {
                throw IllegalStateException("No transaction preview is available.")
            }
            val response = connection.inputStream.bufferedReader().use { it.readText() }
            val data = JSONObject(response).getJSONObject("data")
            val preview = TransactionPreview.fromJson(data)
            validateTransactionPreview(preview, credentialId)
            return preview
        } finally {
            connection.disconnect()
        }
    }

    private fun validateTransactionPreview(preview: TransactionPreview, credentialId: String) {
        if (preview.credentialId != credentialId ||
            preview.expiresAt < System.currentTimeMillis() / 1000 ||
            preview.transactions.isEmpty() || preview.transactions.size > 16
        ) {
            throw IllegalStateException("The transaction preview is invalid or expired.")
        }

        val req = request ?: throw IllegalStateException("No passkey request is available.")
        val rawRequestJson = bundleRequestJson ?: run {
            val option = req.credentialOptions.firstOrNull { it is GetPublicKeyCredentialOption }
                as? GetPublicKeyCredentialOption
                ?: throw IllegalStateException("No passkey request is available.")
            option.requestJson
        }
        val requestJson = JSONObject(rawRequestJson)
        val publicKey = if (requestJson.has("publicKey")) requestJson.getJSONObject("publicKey") else requestJson
        if (publicKey.optString("challenge") != preview.challenge) {
            throw IllegalStateException("The preview does not match this transaction request.")
        }
        val systemClientDataHash = req.credentialOptions
            .filterIsInstance<GetPublicKeyCredentialOption>()
            .firstOrNull { option ->
                option.requestJson == rawRequestJson || try {
                    JSONObject(option.requestJson).toString() == JSONObject(rawRequestJson).toString()
                } catch (_: Exception) {
                    false
                }
            }
            ?.requestData
            ?.getByteArray("androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH")
            ?: throw IllegalStateException("The browser did not provide a verifiable passkey request.")
        val escapedChallenge = JSONObject.quote(preview.challenge)
        val escapedOrigin = JSONObject.quote(preview.origin)
        val candidates = listOf(
            "{\"type\":\"webauthn.get\",\"challenge\":$escapedChallenge,\"origin\":$escapedOrigin,\"crossOrigin\":false}",
            "{\"type\":\"webauthn.get\",\"challenge\":$escapedChallenge,\"origin\":$escapedOrigin}"
        )
        if (candidates.none {
                MessageDigest.getInstance("SHA-256").digest(it.toByteArray(Charsets.UTF_8))
                    .contentEquals(systemClientDataHash)
            }) {
            throw IllegalStateException("The preview does not match this passkey request.")
        }
    }

    private suspend fun confirmTransactionPreview(preview: TransactionPreview): Boolean =
        suspendCoroutine { continuation ->
            val lines = preview.transactions.mapIndexed { index, transaction ->
                "${index + 1}. ${transaction.displayText()}"
            }.joinToString("\n")
            AlertDialog.Builder(this)
                .setTitle("Approve transaction group?")
                .setMessage(lines)
                .setNegativeButton("Cancel") { _, _ -> continuation.resume(false) }
                .setPositiveButton("Continue") { _, _ -> continuation.resume(true) }
                .setOnCancelListener { continuation.resume(false) }
                .show()
        }

    private fun setupPreviewLoadingUI() {
        val label = TextView(this).apply {
            text = "Checking transaction group…"
            textSize = 17f
            gravity = Gravity.CENTER
            setPadding(32, 32, 32, 32)
        }
        setContentView(label)
    }

    private fun showPreviewFailure(message: String) {
        AlertDialog.Builder(this)
            .setTitle("Transaction approval unavailable")
            .setMessage(message)
            .setCancelable(false)
            .setNegativeButton("Cancel") { _, _ ->
                setResult(RESULT_CANCELED)
                finish()
            }
            .show()
    }

    private fun setupUI() {
        if (isFinishing || isDestroyed) return
        
        // Improved UI
        val layout = LinearLayout(this).apply {
            val padding = (32 * resources.displayMetrics.density).toInt()
            orientation = LinearLayout.VERTICAL
            setPadding(padding, padding, padding, padding)
            gravity = Gravity.CENTER_HORIZONTAL
            setBackgroundColor(Color.WHITE)
        }

        // Header with App Icon and Provider Label
        try {
            val appInfo = packageManager.getApplicationInfo(packageName, 0)
            val appIcon = packageManager.getApplicationIcon(appInfo)
            val appLabel = packageManager.getApplicationLabel(appInfo)

            val density = resources.displayMetrics.density
            val iconSize = (48 * density).toInt()
            val iconMargin = (12 * density).toInt()
            val headerPadding = (40 * density).toInt()

            val header = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, 0, 0, headerPadding)
            }

            val iconView = ImageView(this).apply {
                setImageDrawable(appIcon)
                layoutParams = LinearLayout.LayoutParams(iconSize, iconSize).apply {
                    marginEnd = iconMargin
                }
            }
            header.addView(iconView)

            val providerLabel = TextView(this).apply {
                text = appLabel
                textSize = 16f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(Color.DKGRAY)
            }
            header.addView(providerLabel)
            layout.addView(header)
        } catch (e: Exception) {
            // Fallback if app info cannot be loaded
        }

        val title = TextView(this).apply {
            text = "Use Passkey"
            textSize = 28f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 0, (8 * resources.displayMetrics.density).toInt())
            setTextColor(Color.BLACK)
        }
        layout.addView(title)

        val description = TextView(this).apply {
            text = "Sign in to $displayOrigin"
            textSize = 16f
            setPadding(0, 0, 0, (40 * resources.displayMetrics.density).toInt())
            gravity = Gravity.CENTER_HORIZONTAL
            setTextColor(Color.GRAY)
        }
        layout.addView(description)

        val userInfoContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 0, 0, (50 * resources.displayMetrics.density).toInt())
            gravity = Gravity.CENTER_HORIZONTAL
        }

        val userLabel = TextView(this).apply {
            text = "ACCOUNT"
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.GRAY)
            setPadding(0, 0, 0, (4 * resources.displayMetrics.density).toInt())
        }
        userInfoContainer.addView(userLabel)

        val userValue = TextView(this).apply {
            text = userHandle
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.BLACK)
        }
        userInfoContainer.addView(userValue)
        layout.addView(userInfoContainer)

        val confirmButton = Button(this).apply {
            text = "Sign In"
            // Stable accessibility id for E2E tests (`~get-passkey-confirm`).
            contentDescription = "get-passkey-confirm"
            setOnClickListener {
                handleAssertion()
            }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(0, 0, 0, (8 * resources.displayMetrics.density).toInt())
            }
        }
        layout.addView(confirmButton)

        val cancelButton = Button(this, null, android.R.attr.borderlessButtonStyle).apply {
            text = "Cancel"
            contentDescription = "get-passkey-cancel"
            setOnClickListener {
                setResult(RESULT_CANCELED)
                finish()
            }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }
        layout.addView(cancelButton)

        setContentView(layout)
        
        // Ensure the activity is focusable and can receive touches
        layout.isFocusable = true
        layout.isFocusableInTouchMode = true
        layout.requestFocus()
    }

    @SuppressLint("RestrictedApi")
    private fun handleAssertion() {
        if (isHandling) return
        isHandling = true
        Log.d(TAG, "handleAssertion started, userVerification=$userVerification")
        lifecycleScope.launch {
            val credentialData = intent.getBundleExtra("CREDENTIAL_DATA")
            val biometricIv = credentialData?.getString("biometricIv")
            Log.d(TAG, "biometricIv from bundle: $biometricIv")
            
            val cipherToUse = systemUnlockedCipher ?: run {
                if (biometricPromptResult != null) {
                    try {
                        val fallback = if (biometricIv != null) {
                            credentialRepository.getBiometricCipherForDecryption(AndroidBase64.decode(biometricIv, AndroidBase64.DEFAULT))
                        } else {
                            credentialRepository.getBiometricCipherForEncryption()
                        }
                        Log.i(TAG, "Successfully obtained fallback cipher from repository (Single Tap timeout)")
                        fallback
                    } catch (e: Exception) {
                        Log.d(TAG, "Fallback cipher failed: ${e.message}")
                        null
                    }
                } else {
                    null
                }
            } ?: run {
                // Only prompt for manual biometrics if userVerification is "required" 
                // OR if the key was saved with biometric protection (biometricIv != null)
                if (userVerification == "required" || biometricIv != null) {
                    Log.i(TAG, "Manual biometrics required (userVerification=$userVerification, biometricIv present=${biometricIv != null})")
                    val result = biometrics(biometricIv)
                    Log.d(TAG, "Manual biometrics result: $result")
                    if (result == null) {
                        Log.w(TAG, "Biometrics failed or was canceled")
                        setupUI() // Show UI as fallback
                        isHandling = false
                        return@launch
                    }
                    result.cryptoObject?.cipher
                } else {
                    Log.d(TAG, "userVerification is $userVerification and key is not locked, skipping manual biometrics")
                    null
                }
            }
            
            Log.d(TAG, "cipherToUse: $cipherToUse")
            
            var finalCipher = cipherToUse

            try {
                val req = request ?: throw IllegalStateException("No request found")
                Log.d(TAG, "Request found, origin: $origin")
            
            // Prefer using the request JSON from the bundle if available, as it's specifically for this entry
            val rawRequestJson = bundleRequestJson ?: run {
                val option = req.credentialOptions[0] as GetPublicKeyCredentialOption
                option.requestJson
            }
            
            val requestJson = JSONObject(rawRequestJson)
            val passkeyReqJson = if (requestJson.has("publicKey")) {
                requestJson.getJSONObject("publicKey").toString()
            } else {
                rawRequestJson
            }
            Log.d(TAG, "Passkey request JSON: $passkeyReqJson")
            val requestOptions = try {
                PublicKeyCredentialRequestOptions(passkeyReqJson)
            } catch (e: org.json.JSONException) {
                Log.e(TAG, "Invalid passkey request JSON: $passkeyReqJson")
                throw e
            }

            val credId = AndroidBase64.decode(credentialIdEnc!!, AndroidBase64.DEFAULT)
            Log.d(TAG, "Credential ID decoded")

            val passkeyRequestJsonObj = JSONObject(passkeyReqJson)
            val challenge = if (passkeyRequestJsonObj.has("challenge")) {
                passkeyRequestJsonObj.getString("challenge")
            } else {
                throw org.json.JSONException("No value for challenge in requestJson: $passkeyReqJson")
            }
            val sanitizedOrigin = origin.replace(Regex("/$"), "")

            // Look for system-provided clientDataHash (e.g. from Chrome)
            val systemClientDataHash = run {
                val option = req.credentialOptions.find { opt ->
                    opt is GetPublicKeyCredentialOption && (opt.requestJson == rawRequestJson || 
                        try { JSONObject(opt.requestJson).toString() == JSONObject(rawRequestJson!!).toString() } catch(e: Exception) { false })
                } as? GetPublicKeyCredentialOption
                option?.requestData?.getByteArray("androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH")
            }
            Log.d(TAG, "systemClientDataHash present: ${systemClientDataHash != null}")

            Log.d(TAG, "Building clientDataJSON, challenge: $challenge, origin: $sanitizedOrigin")
            val clientDataJSONString = if (sanitizedOrigin.startsWith("https://") || sanitizedOrigin.startsWith("http://")) {
                // Compact JSON for web origins to match browser hashing (no spaces, specific order)
                "{\"type\":\"webauthn.get\",\"challenge\":\"$challenge\",\"origin\":\"$sanitizedOrigin\",\"crossOrigin\":false}"
            } else {
                val json = JSONObject()
                json.put("type", "webauthn.get")
                json.put("challenge", challenge)
                json.put("origin", sanitizedOrigin)
                json.put("crossOrigin", false)
                if (sanitizedOrigin.startsWith("android:apk-key-hash:")) {
                    json.put("androidPackageName", req.callingAppInfo.packageName)
                }
                json.toString()
            }

            val clientDataHash = systemClientDataHash ?: MessageDigest.getInstance("SHA-256").digest(clientDataJSONString.toByteArray(Charsets.UTF_8))

            Log.d(TAG, "Getting credential from repository")
            val dbCred = try {
                credentialRepository.getCredential(this@GetPasskeyActivity, credId, finalCipher)
                    ?: throw IllegalStateException("Credential not found")
            } catch (e: Exception) {
                if (e.message?.contains("user not authenticated", ignoreCase = true) == true || 
                    e.cause?.message?.contains("user not authenticated", ignoreCase = true) == true) {
                    Log.i(TAG, "Key is locked, triggering manual biometric prompt")
                    val result = biometrics(biometricIv)
                    if (result != null) {
                        finalCipher = result.cryptoObject?.cipher
                        Log.i(TAG, "Retrying getCredential with manual biometric cipher")
                        credentialRepository.getCredential(this@GetPasskeyActivity, credId, finalCipher)
                            ?: throw IllegalStateException("Credential not found after manual prompt")
                    } else {
                        throw e
                    }
                } else {
                    throw e
                }
            }

            Log.d(TAG, "Building AuthenticatorAssertionResponse")
            val response = AuthenticatorAssertionResponse(
                requestOptions = requestOptions,
                credentialId = credId,
                origin = sanitizedOrigin,
                up = true,
                uv = true,
                be = true,
                bs = true,
                userHandle = AndroidBase64.decode(dbCred.userId, AndroidBase64.URL_SAFE),
                packageName = req.callingAppInfo.packageName,
                clientDataHash = clientDataHash
            )

            Log.d(TAG, "Getting key pair for signing")
            val keyPair = try {
                credentialRepository.getKeyPair(this@GetPasskeyActivity, credId, finalCipher)
                    ?: throw IllegalStateException("No keypair found")
            } catch (e: Exception) {
                // If we get here, it means getCredential succeeded but something went wrong with getKeyPair.
                // We shouldn't need a second prompt here if we already got the cipher, but for safety:
                if (e.message?.contains("user not authenticated", ignoreCase = true) == true || 
                    e.cause?.message?.contains("user not authenticated", ignoreCase = true) == true) {
                     Log.i(TAG, "Key is locked for signing, triggering manual biometric prompt")
                     val result = biometrics(biometricIv)
                     if (result != null) {
                         finalCipher = result.cryptoObject?.cipher
                         credentialRepository.getKeyPair(this@GetPasskeyActivity, credId, finalCipher)
                             ?: throw IllegalStateException("No keypair found after manual prompt")
                     } else {
                         throw e
                     }
                } else {
                    throw e
                }
            }

            Log.d(TAG, "Signing response")
            response.signature = credentialRepository.sign(keyPair, response.dataToSign())

            val fidoCredential = FidoPublicKeyCredential(
                rawId = credId,
                response = response,
                authenticatorAttachment = "platform"
            )

            // Manual addition of clientDataJSON and signature to the response JSON
            val clientDataJSONb64 = AndroidBase64.encodeToString(clientDataJSONString.toByteArray(), AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING)
            val signatureb64 = AndroidBase64.encodeToString(response.signature, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING)

            val fullJson = JSONObject(fidoCredential.json())
            val respJson = fullJson.getJSONObject("response")
            respJson.put("clientDataJSON", clientDataJSONb64)
            respJson.put("signature", signatureb64)

            // Add clientExtensionResults as seen in the example
            val clientExtensionResults = JSONObject()
            val credProps = JSONObject()
            credProps.put("rk", true)
            clientExtensionResults.put("credProps", credProps)
            fullJson.put("clientExtensionResults", clientExtensionResults)

            val credentialJson = fullJson.toString()
            Log.d(TAG, "Final credential JSON: $credentialJson")

            val resultIntent = Intent()
            val passkeyCredential = PublicKeyCredential(credentialJson)

            PendingIntentHandler.setGetCredentialResponse(
                resultIntent,
                GetCredentialResponse(passkeyCredential)
            )

            setResult(Activity.RESULT_OK, resultIntent)
            Log.d(TAG, "Result set to OK")
            ReactNativePasskeyAutofillModule.instance?.sendEvent("onPasskeyAuthenticated", Bundle().apply {
                putBoolean("success", true)
            })
            finish()
        } catch (e: Exception) {
            Log.e(TAG, "Error during passkey assertion", e)
            setupUI() // Show UI on error
            isHandling = false
        }
    }
    }

    private suspend fun biometrics(iv: String?): BiometricPrompt.AuthenticationResult? {
        return suspendCoroutine { continuation ->
            val biometricPrompt = BiometricPrompt(
                this,
                ContextCompat.getMainExecutor(this),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        continuation.resume(result)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        continuation.resume(null)
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                    }
                }
            )
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Sign In")
                .setSubtitle("Authenticate to use your passkey")
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()
            
            if (iv != null) {
                try {
                    val ivBytes = AndroidBase64.decode(iv, AndroidBase64.DEFAULT)
                    val cipher = credentialRepository.getBiometricCipherForDecryption(ivBytes)
                    biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to initialize biometric prompt with cipher", e)
                    biometricPrompt.authenticate(promptInfo)
                }
            } else {
                biometricPrompt.authenticate(promptInfo)
            }
        }
    }
}

private data class TransactionPreview(
    val credentialId: String,
    val challenge: String,
    val origin: String,
    val expiresAt: Long,
    val transactions: List<TransactionPreviewTransaction>
) {
    companion object {
        fun fromJson(json: JSONObject): TransactionPreview {
            val encodedTransactions = json.getJSONArray("transactions")
            val transactions = (0 until encodedTransactions.length()).map { index ->
                val transaction = encodedTransactions.getJSONObject(index)
                TransactionPreviewTransaction(
                    type = transaction.getString("type"),
                    sender = transaction.getString("sender"),
                    receiver = transaction.optString("receiver").takeIf { it.isNotEmpty() },
                    amount = transaction.optLong("amount").takeIf { it > 0 },
                    assetId = transaction.optLong("assetId").takeIf { it > 0 },
                    appId = transaction.optLong("appId").takeIf { it > 0 },
                    method = transaction.optString("method").takeIf { it.isNotEmpty() },
                    fee = transaction.getLong("fee")
                )
            }
            return TransactionPreview(
                credentialId = json.getString("credentialId"),
                challenge = json.getString("challenge"),
                origin = json.getString("origin"),
                expiresAt = json.getLong("expiresAt"),
                transactions = transactions
            )
        }
    }
}

private data class TransactionPreviewTransaction(
    val type: String,
    val sender: String,
    val receiver: String?,
    val amount: Long?,
    val assetId: Long?,
    val appId: Long?,
    val method: String?,
    val fee: Long
) {
    fun displayText(): String {
        val label = when (type) {
            "pay" -> "Payment"
            "axfer" -> "Asset transfer"
            "appl" -> "Application call"
            else -> type
        }
        val details = mutableListOf<String>()
        val abbreviatedSender = if (sender.length > 16) "${sender.take(7)}…${sender.takeLast(5)}" else sender
        details.add("from $abbreviatedSender")
        receiver?.let {
            val abbreviated = if (it.length > 16) "${it.take(7)}…${it.takeLast(5)}" else it
            details.add("to $abbreviated")
        }
        amount?.let { details.add(it.toString()) }
        assetId?.let { details.add("asset $it") }
        appId?.let { details.add("app $it") }
        method?.let { details.add("method $it") }
        details.add("fee $fee µALGO")
        return if (details.isEmpty()) label else "$label · ${details.joinToString(" · ")}"
    }
}
