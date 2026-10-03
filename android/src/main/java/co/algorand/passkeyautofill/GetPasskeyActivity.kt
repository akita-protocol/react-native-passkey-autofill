package co.algorand.passkeyautofill

import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.os.Build
import android.os.Bundle
import co.algorand.passkeyautofill.utils.PasskeyLog
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
import co.algorand.passkeyautofill.auth.BiometricRequirement
import co.algorand.passkeyautofill.auth.UserVerification
import co.algorand.passkeyautofill.credentials.CredentialRepository
import co.algorand.passkeyautofill.credentials.Credential
import co.algorand.passkeyautofill.credentials.KeystoreRecords
import co.algorand.passkeyautofill.credentials.ParentSecretResult
import co.algorand.passkeyautofill.credentials.RelyingParty
import co.algorand.passkeyautofill.credentials.TransactionPreviewPolicy
import co.algorand.passkeyautofill.utils.PasskeyUtils
import co.algorand.passkeyautofill.utils.PrivilegedBrowserAllowlist
import java.security.KeyPair
import java.security.MessageDigest
import java.net.HttpURLConnection
import java.net.URL
import android.util.Base64 as AndroidBase64
import androidx.biometric.BiometricManager
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
    /** The verified web origin when the caller is an allow-listed privileged browser; null for every ordinary app. */
    private var privilegedOrigin: String? = null
    private var userHandle: String = "unknown-user"
    private var credentialIdEnc: String? = null
    private var userVerification: String = "preferred"
    private var bundleRequestJson: String? = null
    private var request: ProviderGetCredentialRequest? = null
    private var biometricPromptResult: Any? = null

    /** The system's Credential Manager prompt ran for this operation and succeeded. */
    private var systemVerified: Boolean = false
    private var systemUnlockedCipher: javax.crypto.Cipher? = null
    private var isHandling: Boolean = false
    private var isLoadingTransactionPreview: Boolean = false
    private var hasApprovedTransactionPreview: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        PasskeyLog.init(this)
        PasskeyLog.i(TAG, "onCreate started")
        
        request = try {
            PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        } catch (e: Exception) {
            PasskeyLog.e(TAG, "Error retrieving request from intent", e)
            null
        }
        PasskeyLog.i(TAG, "Retrieved request: present=${request != null}")
        
        // Check for system-provided biometric result (Single Tap flow)
        try {
            val biometricResult = request?.biometricPromptResult
            PasskeyLog.i(TAG, "biometricResult from system: present=${biometricResult != null}")
            if (biometricResult != null) {
                this.biometricPromptResult = biometricResult
                // A result object alone is not verification: the prompt may
                // have failed or been dismissed.
                systemVerified = biometricResult.isSuccessful
                val authResult = biometricResult.authenticationResult
                PasskeyLog.i(TAG, "authResult from system: present=${authResult != null}, successful=$systemVerified")
                
                // Also try to find it in the biometricResult object itself
                systemUnlockedCipher = if (authResult != null) {
                    PasskeyUtils.extractCipher(authResult)
                } else {
                    PasskeyUtils.extractCipher(biometricResult)
                }
                PasskeyLog.i(TAG, "systemUnlockedCipher from system: present=${systemUnlockedCipher != null}")
            }
        } catch (e: Exception) {
            PasskeyLog.e(TAG, "Error processing biometricPromptResult", e)
        }

        val credentialData = intent.getBundleExtra("CREDENTIAL_DATA")

        if (credentialData != null) {
            credentialIdEnc = credentialData.getString("credentialId")
            userHandle = credentialData.getString("userHandle") ?: "unknown-user"
            bundleRequestJson = credentialData.getString("requestJson")
            userVerification = credentialData.getString("userVerification") ?: "preferred"
        }

        if (request != null) {
            // A caller-asserted web origin is trusted only for an allow-listed
            // privileged browser; everyone else is bound to their app identity.
            val allowlist = PrivilegedBrowserAllowlist.json(this)
            privilegedOrigin = allowlist?.let {
                credentialRepository.getPrivilegedOrigin(request!!.callingAppInfo, it)
            }
            origin = privilegedOrigin ?: credentialRepository.getOrigin(request!!.callingAppInfo)
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
            PasskeyLog.d(TAG, "System already showed biometric prompt (Single Tap), proceeding automatically")
            beginAssertionFlow()
            return
        }

        // Auto-trigger assertion flow
        beginAssertionFlow()
    }

    /**
     * Akita: a credential configured for transaction previews shows the pending
     * transaction group, fetched from the Akita API and bound to this request's
     * client data, and waits for approval before the assertion can run.
     */
    private fun beginAssertionFlow() {
        if (isHandling || isLoadingTransactionPreview) return
        lifecycleScope.launch {
            try {
                val credential = credentialIdEnc?.let {
                    credentialRepository.getCredentialMetadata(
                        this@GetPasskeyActivity,
                        AndroidBase64.decode(it, AndroidBase64.DEFAULT),
                    )
                }
                if (credential?.showTransactionRequests == true && !hasApprovedTransactionPreview) {
                    isLoadingTransactionPreview = true
                    setupPreviewLoadingUI()
                    val preview = try {
                        withContext(Dispatchers.IO) { fetchAndValidateTransactionPreview(credential) }
                    } finally {
                        isLoadingTransactionPreview = false
                    }
                    if (!confirmTransactionPreview(preview)) {
                        setResult(RESULT_CANCELED)
                        finish()
                        return@launch
                    }
                    hasApprovedTransactionPreview = true
                }
                handleAssertion()
            } catch (error: Exception) {
                PasskeyLog.e(TAG, "Required transaction preview failed", error)
                showPreviewFailure(error.message ?: "The required transaction preview could not be verified.")
            }
        }
    }

    private fun fetchAndValidateTransactionPreview(credential: Credential): TransactionPreview {
        // Closed policy: an incomplete or non-origin configuration fails here.
        val policy = credential.transactionPreviewPolicy() as? TransactionPreviewPolicy.Required
            ?: throw IllegalStateException("Transaction preview is required but is not configured.")
        val token = policy.token
        val base = URL(policy.httpsEndpoint)
        val credentialIdBytes = AndroidBase64.decode(credential.credentialId, AndroidBase64.DEFAULT)
        val credentialId = AndroidBase64.encodeToString(
            credentialIdBytes,
            AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING
        )
        val endpoint = URL(base, "/akita/passkey-previews/$credentialId")
        val connection = endpoint.openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "GET"
            // The bearer token goes to the configured origin only: no redirects,
            // no cached or cookie-bearing state.
            connection.instanceFollowRedirects = false
            connection.useCaches = false
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
        // Only an allow-listed privileged browser's clientDataHash is ever signed
        // (see handleAssertion), so only that hash can bind a preview to a request.
        if (privilegedOrigin == null) {
            throw IllegalStateException("The browser did not provide a verifiable passkey request.")
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
                beginAssertionFlow()
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

    private fun setupErrorUI(message: String, allowRetry: Boolean) {
        if (isFinishing || isDestroyed) return

        val layout = LinearLayout(this).apply {
            val padding = (32 * resources.displayMetrics.density).toInt()
            orientation = LinearLayout.VERTICAL
            setPadding(padding, padding, padding, padding)
            gravity = Gravity.CENTER_HORIZONTAL
            setBackgroundColor(Color.WHITE)
        }

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
        }

        val title = TextView(this).apply {
            text = "Couldn't sign in"
            textSize = 28f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 0, (8 * resources.displayMetrics.density).toInt())
            setTextColor(Color.BLACK)
        }
        layout.addView(title)

        val description = TextView(this).apply {
            text = message
            textSize = 16f
            setPadding(0, 0, 0, (40 * resources.displayMetrics.density).toInt())
            gravity = Gravity.CENTER_HORIZONTAL
            setTextColor(Color.GRAY)
        }
        layout.addView(description)

        if (allowRetry) {
            val retryButton = Button(this).apply {
                text = "Try Again"
                contentDescription = "get-passkey-retry"
                setOnClickListener {
                    beginAssertionFlow()
                }
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    setMargins(0, 0, 0, (8 * resources.displayMetrics.density).toInt())
                }
            }
            layout.addView(retryButton)
        }

        val closeButton = Button(this, null, android.R.attr.borderlessButtonStyle).apply {
            text = "Close"
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
        layout.addView(closeButton)

        setContentView(layout)

        layout.isFocusable = true
        layout.isFocusableInTouchMode = true
        layout.requestFocus()
    }

    @SuppressLint("RestrictedApi")
    private fun handleAssertion() {
        if (isHandling) return
        isHandling = true
        PasskeyLog.d(TAG, "handleAssertion started, userVerification=$userVerification")
        lifecycleScope.launch {
            val credentialData = intent.getBundleExtra("CREDENTIAL_DATA")
            val biometricIv = credentialData?.getString("biometricIv")
            PasskeyLog.d(TAG, "biometricIv from bundle: present=${biometricIv != null}")
            
            // A manual BiometricPrompt this activity showed succeeded.
            var manualVerified = false
            var cipherToUse = systemUnlockedCipher ?: run {
                if (biometricPromptResult != null) {
                    try {
                        val requirement = BiometricRequirement.resolve(this@GetPasskeyActivity)
                        val fallback = if (biometricIv != null) {
                            credentialRepository.getBiometricCipherForDecryption(this@GetPasskeyActivity, AndroidBase64.decode(biometricIv, AndroidBase64.DEFAULT), requirement)
                        } else {
                            credentialRepository.getBiometricCipherForEncryption(this@GetPasskeyActivity, requirement)
                        }
                        PasskeyLog.i(TAG, "Successfully obtained fallback cipher from repository (Single Tap timeout)")
                        fallback
                    } catch (e: Exception) {
                        PasskeyLog.d(TAG, "Fallback cipher failed: ${e.message}")
                        null
                    }
                } else {
                    null
                }
            }

            // A manual prompt is needed when the relying party REQUIRES
            // verification and the system's prompt did not succeed, or when the
            // key is biometric-wrapped and we hold no unlocked cipher for it.
            // "preferred"/"discouraged" with an unwrapped key proceed without a
            // ceremony — and the response's UV flag says so.
            val requiresCeremony =
                UserVerification.normalize(userVerification) == UserVerification.REQUIRED && !systemVerified
            val needsCipher = cipherToUse == null && biometricIv != null
            run {
                if (requiresCeremony || needsCipher) {
                    PasskeyLog.i(TAG, "Manual biometrics required (userVerification=$userVerification, biometricIv present=${biometricIv != null})")
                    val result = biometrics(biometricIv)
                    if (result == null) {
                        PasskeyLog.w(TAG, "Biometrics failed or was canceled")
                        val requirement = BiometricRequirement.resolve(this@GetPasskeyActivity)
                        val canUseBiometrics =
                            BiometricManager.from(this@GetPasskeyActivity)
                                .canAuthenticate(
                                    requirement.allowedAuthenticators,
                                ) == BiometricManager.BIOMETRIC_SUCCESS
                        if (canUseBiometrics) {
                            setupUI()
                        } else {
                            setupErrorUI(
                                "This device has no screen lock or biometric set up, which passkeys require. Add one in your device settings, then try again.",
                                allowRetry = false,
                            )
                        }
                        isHandling = false
                        return@launch
                    }
                    manualVerified = true
                    cipherToUse = result.cryptoObject?.cipher ?: cipherToUse
                } else if (!systemVerified) {
                    PasskeyLog.d(TAG, "userVerification is $userVerification and key is not locked, skipping manual biometrics")
                }
            }

            var finalCipher = cipherToUse

            try {
                val req = request ?: throw IllegalStateException("No request found")
                PasskeyLog.d(TAG, "Request found")
            
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
            val requestOptions = try {
                PublicKeyCredentialRequestOptions(passkeyReqJson)
            } catch (e: org.json.JSONException) {
                PasskeyLog.e(TAG, "Invalid passkey request JSON")
                throw e
            }

            val credId = AndroidBase64.decode(credentialIdEnc!!, AndroidBase64.DEFAULT)
            PasskeyLog.d(TAG, "Credential ID decoded")

            val passkeyRequestJsonObj = JSONObject(passkeyReqJson)
            val challenge = if (passkeyRequestJsonObj.has("challenge")) {
                passkeyRequestJsonObj.getString("challenge")
            } else {
                throw org.json.JSONException("No value for challenge in requestJson")
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
            PasskeyLog.d(TAG, "systemClientDataHash present: ${systemClientDataHash != null}")

            PasskeyLog.d(TAG, "Building clientDataJSON")
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

            // Only an allow-listed privileged browser may have its own
            // clientDataHash (and web origin) trusted. For every other caller we
            // IGNORE any supplied hash and sign OUR OWN hash of the app-bound
            // clientDataJSON, so the assertion is bound to the caller's
            // android:apk-key-hash: identity and a foreign RP rejects it.
            val trustSystemHash = privilegedOrigin != null && systemClientDataHash != null
            if (systemClientDataHash != null && !trustSystemHash) {
                PasskeyLog.w(TAG, "Ignoring caller-supplied clientDataHash from non-privileged caller; binding assertion to app origin")
            }
            val clientDataHash = if (trustSystemHash) {
                systemClientDataHash!!
            } else {
                MessageDigest.getInstance("SHA-256").digest(clientDataJSONString.toByteArray(Charsets.UTF_8))
            }

            // Metadata only: everything the response needs before signing (user
            // handle, derivation pins) is read without touching the private key.
            // The key itself is materialised exactly once, in getKeyPair below.
            PasskeyLog.d(TAG, "Getting credential metadata from repository")
            val dbCred = credentialRepository.getCredentialMetadata(this@GetPasskeyActivity, credId)
                ?: throw IllegalStateException("Credential not found")

            // The chooser is RP-scoped, but the pending intent carries whatever
            // credential id it was built with: re-establish the invariant here,
            // before any private material is loaded.
            val requestedRpId = RelyingParty.effectiveRpId(passkeyReqJson, origin)
            if (requestedRpId == null || !RelyingParty.matches(dbCred.origin, requestedRpId)) {
                PasskeyLog.e(TAG, "Credential is not scoped to the requesting relying party; refusing to sign")
                setupErrorUI(
                    "This passkey was created for a different site or app and cannot be used here.",
                    allowRetry = false,
                )
                isHandling = false
                return@launch
            }

            PasskeyLog.d(TAG, "Getting key pair for signing")
            val keyPair = try {
                credentialRepository.getKeyPair(this@GetPasskeyActivity, credId, finalCipher)
                    ?: throw IllegalStateException("No keypair found")
            } catch (e: Exception) {
                // The metadata read above cannot trip a user-authentication
                // requirement; opening the private material here can, when the
                // record is biometric-wrapped and the cipher was not yet unlocked.
                if (e.message?.contains("user not authenticated", ignoreCase = true) == true || 
                    e.cause?.message?.contains("user not authenticated", ignoreCase = true) == true) {
                     PasskeyLog.i(TAG, "Key is locked for signing, triggering manual biometric prompt")
                     val result = biometrics(biometricIv)
                     if (result != null) {
                         manualVerified = true
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

            // UV reflects what actually happened in this operation. UP stays set:
            // the user chose this credential's entry in the system chooser (or
            // tapped Sign In in our sheet), which is the presence gesture. The
            // response is built after every prompt this flow can show, so the
            // flag cannot go stale.
            val verification = UserVerification.outcome(userVerification, systemVerified, manualVerified)
            check(verification.satisfiesRequest) {
                "Relying party requires user verification but no verification ceremony completed"
            }
            PasskeyLog.d(TAG, "Building AuthenticatorAssertionResponse (uv=${verification.verified})")
            val response = AuthenticatorAssertionResponse(
                requestOptions = requestOptions,
                credentialId = credId,
                origin = sanitizedOrigin,
                up = true,
                uv = verification.verified,
                be = true,
                bs = true,
                userHandle = AndroidBase64.decode(dbCred.userId, AndroidBase64.URL_SAFE),
                packageName = req.callingAppInfo.packageName,
                clientDataHash = clientDataHash
            )

            PasskeyLog.d(TAG, "Signing response")
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
            // When a privileged browser's own hash was signed, our clientDataJSON
            // is not what was signed (the browser supplies its own), so we do not
            // attach it. For all app-bound callers we attach the clientDataJSON
            // whose hash we signed.
            if (!trustSystemHash) {
                respJson.put("clientDataJSON", clientDataJSONb64)
            }
            respJson.put("signature", signatureb64)

            // Add clientExtensionResults as seen in the example
            val clientExtensionResults = JSONObject()
            val credProps = JSONObject()
            credProps.put("rk", true)
            clientExtensionResults.put("credProps", credProps)

            // WebAuthn `prf` extension (hmac-secret). If the RP requested PRF
            // evaluation for this assertion, derive the per-credential
            // `credRandom` from the wallet HD root secret and compute
            // HMAC-SHA256-based outputs for the supplied salt(s).
            try {
                val credentialIdB64Url = AndroidBase64.encodeToString(
                    credId,
                    AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING,
                )
                val prfInput = Prf.parseInput(passkeyRequestJsonObj, credentialIdB64Url)
                if (prfInput != null) {
                    // PRF is recomputed from the parent secret on EVERY assertion,
                    // so it must use the very parent this credential was created
                    // against — an unstamped credential predates the dp256 main
                    // key and is pinned to the BIP32-Ed25519 root.
                    val parent = credentialRepository.resolveParentSecret(
                        this@GetPasskeyActivity,
                        dbCred.derivationScheme ?: KeystoreRecords.SCHEME_BIP32_ED25519,
                    )
                    if (parent !is ParentSecretResult.Available) {
                        PasskeyLog.w(TAG, "PRF input present but parent secret unavailable (${parent.reason}); skipping PRF output")
                    } else {
                        val credRandom = Prf.credRandom(
                            hdRootSecret = parent.secret.bytes,
                            relyingPartyIdentifier = displayOrigin,
                            userHandle = dbCred.userHandle,
                        )
                        val first = Prf.evaluate(credRandom, prfInput.first, prfInput.alreadyHashed)
                        val second = prfInput.second?.let { Prf.evaluate(credRandom, it, prfInput.alreadyHashed) }

                        val prfResults = JSONObject().put("first", Prf.encodeOutput(first))
                        if (second != null) {
                            prfResults.put("second", Prf.encodeOutput(second))
                        }
                        clientExtensionResults.put("prf", JSONObject().put("results", prfResults))
                        PasskeyLog.d(TAG, "Computed PRF assertion output (second present=${second != null})")
                    }
                }
            } catch (e: Exception) {
                // Never fail the assertion because of a PRF error; just log
                // and omit the extension result.
                PasskeyLog.w(TAG, "Failed to compute PRF assertion output", e)
            }

            fullJson.put("clientExtensionResults", clientExtensionResults)

            // Never logged: the response carries the signature and, when the
            // relying party asked for it, the PRF output.
            val credentialJson = fullJson.toString()

            val resultIntent = Intent()
            val passkeyCredential = PublicKeyCredential(credentialJson)

            PendingIntentHandler.setGetCredentialResponse(
                resultIntent,
                GetCredentialResponse(passkeyCredential)
            )

            setResult(Activity.RESULT_OK, resultIntent)
            PasskeyLog.d(TAG, "Result set to OK")
            credentialRepository.recordCredentialUsage(this@GetPasskeyActivity, credId)
            ReactNativePasskeyAutofillModule.instance?.sendEvent("onPasskeyAuthenticated", Bundle().apply {
                putBoolean("success", true)
                putString("credentialId", credentialIdEnc)
            })
            finish()
        } catch (e: Exception) {
            PasskeyLog.e(TAG, "Error during passkey assertion", e)
            setupErrorUI(
                "Something went wrong while signing in. Please try again.",
                allowRetry = true,
            )
            isHandling = false
        }
    }
    }

    private suspend fun biometrics(iv: String?): BiometricPrompt.AuthenticationResult? {
        val requirement = BiometricRequirement.resolve(this)
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
            val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Sign In")
                .setSubtitle("Authenticate to use your passkey")
                .setAllowedAuthenticators(requirement.allowedAuthenticators)
            if (!requirement.allowsDeviceCredential) {
                promptInfoBuilder.setNegativeButtonText("Cancel")
            }
            val promptInfo = promptInfoBuilder.build()

            if (iv != null && requirement.isCryptoBound) {
                try {
                    val ivBytes = AndroidBase64.decode(iv, AndroidBase64.DEFAULT)
                    val cipher = credentialRepository.getBiometricCipherForDecryption(this, ivBytes, requirement)
                    biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
                } catch (e: Exception) {
                    PasskeyLog.e(TAG, "Failed to initialize biometric prompt with cipher", e)
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
        return "$label · ${details.joinToString(" · ")}"
    }
}
