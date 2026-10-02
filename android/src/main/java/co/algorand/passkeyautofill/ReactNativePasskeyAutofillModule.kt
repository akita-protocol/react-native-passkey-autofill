package co.algorand.passkeyautofill

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import co.algorand.passkeyautofill.credentials.Credential
import co.algorand.passkeyautofill.credentials.CredentialRepository
import co.algorand.passkeyautofill.service.PasskeyAutofillCredentialProviderService
import co.algorand.passkeyautofill.service.PasskeyAutofillCredentialProviderService.Companion.KEY_LAST_INVOKED_AT_MS
import com.tencent.mmkv.MMKV
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.util.Log
import android.util.Base64 as AndroidBase64
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class ReactNativePasskeyAutofillModule : Module() {
  private val credentialRepository = CredentialRepository()

  companion object {
    var instance: ReactNativePasskeyAutofillModule? = null
  }

  init {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
    Security.insertProviderAt(BouncyCastleProvider(), 1)
  }

  // Each module class must implement the definition function. The definition consists of components
  // that describes the module's functionality and behavior.
  // See https://docs.expo.dev/modules/module-api for more details about available components.
  override fun definition() = ModuleDefinition {
    // Sets the name of the module that JavaScript code will use to refer to the module. Takes a string as an argument.
    // Can be inferred from module's class name, but it's recommended to set it explicitly for clarity.
    // The module will be accessible from `requireNativeModule('ReactNativeLiquidAuth')` in JavaScript.
    Name("ReactNativePasskeyAutofill")

    OnCreate {
      instance = this@ReactNativePasskeyAutofillModule
    }

    OnDestroy {
      instance = null
    }

    Events("onPasskeyAdded", "onPasskeyAuthenticated")

    AsyncFunction("setMasterKey") { secret: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.saveMasterKey(context, secret)
      } else {
        Log.e(CredentialRepository.TAG, "Could not get context to save master key")
      }
    }

    AsyncFunction("setHdRootKeyId") { id: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.saveHdRootKeyId(context, id)
      } else {
        Log.e(CredentialRepository.TAG, "Could not get context to save HD root key ID")
      }
    }

    AsyncFunction("setHdRootSecret") { secret: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.saveHdRootSecret(context, secret)
      } else {
        Log.e(CredentialRepository.TAG, "Could not get context to save HD root secret")
      }
    }

    AsyncFunction("getHdRootKeyId") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.getHdRootKeyId(context)
      } else {
        Log.e(CredentialRepository.TAG, "Could not get context to get HD root key ID")
        null
      }
    }

    AsyncFunction("clearCredentials") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: return@AsyncFunction Unit
      credentialRepository.clearCredentials(context)
    }

    AsyncFunction("deleteCredential") { credentialId: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: return@AsyncFunction Unit
      credentialRepository.deleteCredential(context, credentialId)
    }

    AsyncFunction("getStoredCredentials") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: return@AsyncFunction emptyList<Map<String, Any?>>()
      credentialRepository.getAllCredentials(context).map { credential ->
        mapOf(
          "credentialId" to credential.credentialId,
          "relyingPartyIdentifier" to credential.origin,
          "userName" to credential.userId,
          "userHandle" to credential.userHandle,
          "publicKey" to credential.publicKey,
          "showTransactionRequests" to credential.showTransactionRequests,
          "previewApiBaseUrl" to credential.previewApiBaseUrl,
          "previewToken" to credential.previewToken,
          // Platform-independent fields: on Android the legacy userName/userHandle keys
          // carry user.id and user.name respectively, the reverse of iOS.
          "rpId" to credential.origin,
          "userIdBase64Url" to normalizeBase64Url(credential.userId),
          "userDisplayName" to credential.userHandle,
        )
      }
    }

    // Adds synced site passkeys to this device. Each key is re-derived from the
    // wallet's HD root and must reproduce its credential ID; credentials that
    // already exist are left untouched.
    AsyncFunction("restoreDerivedCredentials") { credentials: List<Map<String, Any?>> ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: throw IllegalStateException("No context available to restore passkeys.")
      val existingIds = credentialRepository.getAllCredentials(context).map { it.credentialId }.toSet()
      val restored = mutableListOf<String>()
      val skipped = mutableListOf<Map<String, String>>()

      for (credential in credentials) {
        val reportedId = credential["credentialId"] as? String ?: ""
        val expectedId = decodeBase64Url(reportedId)
        val rpId = credential["rpId"] as? String
        val userIdBase64Url = credential["userIdBase64Url"] as? String
        val handle = credential["derivationHandle"] as? String
        if (expectedId == null || rpId == null || userIdBase64Url == null || handle == null) {
          skipped += mapOf("credentialId" to reportedId, "reason" to "invalid")
          continue
        }
        val storedId = AndroidBase64.encodeToString(expectedId, AndroidBase64.NO_WRAP)
        if (storedId in existingIds) {
          skipped += mapOf("credentialId" to reportedId, "reason" to "exists")
          continue
        }

        try {
          val keyPair = credentialRepository.createDeterministicKeyPair(context, rpId, handle)
          if (!credentialRepository.generateCredentialId(keyPair).contentEquals(expectedId)) {
            skipped += mapOf("credentialId" to reportedId, "reason" to "mismatch")
            continue
          }
          credentialRepository.saveCredential(
            context,
            Credential(
              credentialId = storedId,
              origin = rpId,
              userHandle = credential["userName"] as? String ?: "",
              userId = userIdBase64Url,
              publicKey = AndroidBase64.encodeToString(keyPair.public.encoded, AndroidBase64.NO_WRAP),
              privateKey = AndroidBase64.encodeToString(keyPair.private.encoded, AndroidBase64.NO_WRAP),
              count = 0,
              showTransactionRequests = credential["showTransactionRequests"] as? Boolean ?: false,
              previewApiBaseUrl = credential["previewApiBaseUrl"] as? String,
              previewToken = credential["previewToken"] as? String,
            ),
            null,
          )
          restored += reportedId
        } catch (e: Exception) {
          Log.e(CredentialRepository.TAG, "Failed to restore synced passkey", e)
          skipped += mapOf("credentialId" to reportedId, "reason" to "error")
        }
      }

      mapOf("restored" to restored, "skipped" to skipped)
    }

    AsyncFunction("refreshCredentialIdentities") { Unit }

    AsyncFunction("configureCredentialTransactionPreview") {
      credentialId: String, enabled: Boolean, apiBaseUrl: String, token: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: return@AsyncFunction Unit
      credentialRepository.configureTransactionPreview(context, credentialId, enabled, apiBaseUrl, token)
    }

    AsyncFunction("configureIntentActions") { getPasskeyAction: String, createPasskeyAction: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.configureIntentActions(context, getPasskeyAction, createPasskeyAction)
      }
    }

    AsyncFunction("isProviderActive") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: return@AsyncFunction false
      isProviderEnabled(context)
    }

    AsyncFunction("openProviderSettings") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: return@AsyncFunction false
      openCredentialProviderSettings(context)
    }
  }

  /**
   * Returns `true` when this app's [PasskeyAutofillCredentialProviderService]
   * is registered as an active credential provider for the current user.
   *
   * Android stores the enabled credential providers as a colon-separated list
   * of flattened [ComponentName]s in the `credential_service` and
   * `credential_service_primary` Secure settings (API 34+). However those
   * keys are `@hide` on Android 12+, so reading them from a regular app
   * throws `SecurityException`. We therefore combine two signals:
   *
   *  1. Best-effort: try [Settings.Secure.getString]; if it returns the
   *     expected component we know for sure we're the provider.
   *  2. Fallback: inspect the MMKV timestamp written by the service itself
   *     whenever the system routes a `BeginCreate/BeginGetCredentialRequest`
   *     to it ([PasskeyAutofillCredentialProviderService.KEY_LAST_INVOKED_AT_MS]).
   *     The Credential Manager only routes requests to *enabled* providers,
   *     so a non-zero stamp is proof that we were selected at least once.
   */
  private fun decodeBase64Url(value: String): ByteArray? = try {
    AndroidBase64.decode(value, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING)
  } catch (e: IllegalArgumentException) {
    null
  }

  // user.id is stored as it appeared in the request JSON; return it unpadded.
  private fun normalizeBase64Url(value: String): String =
    decodeBase64Url(value)?.let {
      AndroidBase64.encodeToString(it, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING)
    } ?: value

  private fun isProviderEnabled(context: Context): Boolean {
    val expected = ComponentName(
      context.packageName,
      PasskeyAutofillCredentialProviderService::class.java.name,
    ).flattenToString()
    val resolver = context.contentResolver
    val keys = arrayOf("credential_service", "credential_service_primary")
    for (key in keys) {
      val value = try {
        Settings.Secure.getString(resolver, key)
      } catch (e: SecurityException) {
        // `credential_service[_primary]` are @hide on Android 12+; fall
        // through to the MMKV stamp check below.
        Log.d("ReactNativePasskeyAutofill", "Secure key $key not readable: ${e.message}")
        null
      } ?: continue
      if (value.isEmpty()) continue
      val enabled = value.split(':').any { it.equals(expected, ignoreCase = true) } ||
        value.contains(expected, ignoreCase = true)
      if (enabled) return true
    }
    // Fallback: look for a timestamp written by our CredentialProviderService.
    return try {
      MMKV.initialize(context)
      (MMKV.defaultMMKV()?.decodeLong(KEY_LAST_INVOKED_AT_MS, 0L) ?: 0L) > 0L
    } catch (e: Exception) {
      Log.w("ReactNativePasskeyAutofill", "Failed to read provider stamp: ${e.message}")
      false
    }
  }

  /**
   * Best-effort deep link into the user's credential-provider preferences so
   * they can toggle our service on. Falls back to the app-details page when
   * the credential provider screen is not available on the device.
   */
  private fun openCredentialProviderSettings(context: Context): Boolean {
    val intents = listOf(
      Intent("android.settings.CREDENTIAL_PROVIDER"),
      Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
        data = Uri.fromParts("package", context.packageName, null)
      },
    )
    for (intent in intents) {
      intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      try {
        context.startActivity(intent)
        return true
      } catch (e: Exception) {
        Log.w("ReactNativePasskeyAutofill", "Failed to open ${intent.action}: ${e.message}")
      }
    }
    return false
  }
}
