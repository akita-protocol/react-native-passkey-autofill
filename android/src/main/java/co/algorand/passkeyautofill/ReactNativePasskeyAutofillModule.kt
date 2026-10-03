package co.algorand.passkeyautofill

import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import co.algorand.passkeyautofill.credentials.Credential
import co.algorand.passkeyautofill.credentials.CredentialRepository
import co.algorand.passkeyautofill.credentials.KeystoreRecords
import co.algorand.passkeyautofill.credentials.TransactionPreviewPolicy
import co.algorand.passkeyautofill.service.PasskeyAutofillCredentialProviderService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.util.Base64 as AndroidBase64
import co.algorand.passkeyautofill.utils.PasskeyLog
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/**
 * Rejects the `setMasterKey` promise with code `ERR_MASTER_KEY` when the key
 * could not be stored and verified. The wallet must treat this as "no passkey
 * can be created or asserted on this device" rather than continue.
 */
class MasterKeyException(message: String, cause: Throwable? = null) : CodedException(message, cause)

/** Rejects `setHdRootSecret` with code `ERR_HD_ROOT_SECRET` when the secret could not be stored. */
class HdRootSecretException(message: String, cause: Throwable? = null) : CodedException(message, cause)

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
      ((appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context)?.let { PasskeyLog.init(it) }
    }

    OnDestroy {
      instance = null
    }

    Events("onPasskeyAdded", "onPasskeyAuthenticated")

    // Fails closed: every failure to store and verify the key rejects the
    // promise. Logging and resolving would let the wallet believe the key is in
    // place while credential creation is impossible.
    AsyncFunction("setMasterKey") { secret: ByteArray ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: throw MasterKeyException("Could not get context to save master key")
      try {
        credentialRepository.saveMasterKey(context, secret)
      } catch (e: Exception) {
        PasskeyLog.e(CredentialRepository.TAG, "Failed to save master key", e)
        throw MasterKeyException(e.message ?: "Failed to save master key", e)
      }
    }

    // Points the passkey hierarchy at the wallet's deterministic-P256 main key.
    // The scheme is not a parameter: it is read from the record's own metadata,
    // so a wallet cannot mislabel which hierarchy it handed us.
    AsyncFunction("setMainKeyId") { id: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.saveMainKeyId(context, id)
      } else {
        PasskeyLog.e(CredentialRepository.TAG, "Could not get context to save main key ID")
      }
    }

    // Akita: shares the wallet's HD root secret directly. New passkeys derive from
    // it (scheme `akita-hd-root`). Fails closed like `setMasterKey`.
    AsyncFunction("setHdRootSecret") { secret: ByteArray ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: throw HdRootSecretException("Could not get context to save the HD root secret")
      try {
        credentialRepository.saveHdRootSecret(context, secret)
      } catch (e: Exception) {
        PasskeyLog.e(CredentialRepository.TAG, "Failed to save HD root secret", e)
        throw HdRootSecretException(e.message ?: "Failed to save HD root secret", e)
      }
    }

    AsyncFunction("getMainKeyId") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.getMainKeyId(context)
      } else {
        PasskeyLog.e(CredentialRepository.TAG, "Could not get context to get main key ID")
        null
      }
    }

    // Deprecated aliases of the two above, kept because installed wallets still
    // call them. They address the same slot — see `saveMainKeyId`.
    AsyncFunction("setHdRootKeyId") { id: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.saveMainKeyId(context, id)
      } else {
        PasskeyLog.e(CredentialRepository.TAG, "Could not get context to save HD root key ID")
      }
    }

    AsyncFunction("getHdRootKeyId") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.getMainKeyId(context)
      } else {
        PasskeyLog.e(CredentialRepository.TAG, "Could not get context to get HD root key ID")
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

    AsyncFunction("configureCredentialTransactionPreview") {
      credentialId: String, enabled: Boolean, apiBaseUrl: String, token: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: throw IllegalStateException("No context available to configure the transaction preview.")
      credentialRepository.configureTransactionPreview(context, credentialId, enabled, apiBaseUrl, token)
    }

    AsyncFunction("configureIntentActions") { getPasskeyAction: String, createPasskeyAction: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.configureIntentActions(context, getPasskeyAction, createPasskeyAction)
      }
    }

    // NoOp on Android. iOS uses ASCredentialIdentityStore to advertise
    // credentials to the system AutoFill UI; Android's Credential Manager
    // queries the provider service on demand instead, so there is no
    // equivalent identity store to populate.
    AsyncFunction("replaceCredentialIdentities") { _: List<Map<String, Any?>> ->
      // No-op: see comment above.
    }

    // NoOp on Android. See `replaceCredentialIdentities` above.
    AsyncFunction("refreshCredentialIdentities") {
      // No-op: see comment above.
    }

    // NoOp on Android. iOS exposes diagnostics from the shared App Group
    // store; there is no equivalent on Android yet.
    AsyncFunction("getDiagnostics") {
      emptyList<String>()
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

    AsyncFunction("getStoredCredentials") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: return@AsyncFunction emptyList<Map<String, Any?>>()
      credentialRepository.getAllCredentials(context).map { credential ->
        mapOf(
          "credentialId" to credential.credentialId,
          "relyingPartyIdentifier" to credential.origin,
          "userName" to credential.userHandle,
          "userHandle" to credential.userHandle,
          "publicKey" to credential.publicKey,
          "derivationScheme" to credential.derivationScheme,
          // Akita: the closed preview policy (null when the stored tuple is invalid,
          // which the provider refuses to use), plus its legacy flat fields.
          "transactionPreviewPolicy" to runCatching { credential.transactionPreviewPolicy().toMap() }.getOrNull(),
          "showTransactionRequests" to credential.showTransactionRequests,
          "previewApiBaseUrl" to credential.previewApiBaseUrl,
          "previewToken" to credential.previewToken,
          // Platform-independent fields: Android stores user.name as `userHandle`
          // and user.id as `userId`, so the legacy keys above differ from iOS.
          "rpId" to credential.origin,
          "userIdBase64Url" to normalizeBase64Url(credential.userId),
          "userDisplayName" to credential.userHandle,
        )
      }
    }

    // Akita: adds synced site passkeys to this device. Each key is re-derived from
    // the wallet's HD root (setHdRootSecret) and must reproduce its credential ID;
    // credentials that already exist are left untouched.
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
        // The closed policy or the legacy flat fields, never both, never partial.
        val previewPolicy = try {
          TransactionPreviewPolicy.fromRestoreRecord(credential)
        } catch (e: IllegalArgumentException) {
          skipped += mapOf("credentialId" to reportedId, "reason" to "invalid")
          continue
        }
        val previewRequired = previewPolicy as? TransactionPreviewPolicy.Required

        try {
          // Pinned to the HD root: fails (and the record is skipped) when the
          // wallet has not shared it, rather than deriving from another parent.
          val derived = credentialRepository.createDomainKeyPair(
            context,
            rpId,
            handle,
            requestedScheme = KeystoreRecords.SCHEME_AKITA_HD_ROOT,
            siteHandle = handle,
          )
          if (!credentialRepository.generateCredentialId(derived.keyPair).contentEquals(expectedId)) {
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
              publicKey = AndroidBase64.encodeToString(derived.keyPair.public.encoded, AndroidBase64.NO_WRAP),
              privateKey = AndroidBase64.encodeToString(derived.keyPair.private.encoded, AndroidBase64.NO_WRAP),
              count = 0,
              parentKeyId = derived.parentKeyId,
              derivationScheme = derived.derivationScheme,
              showTransactionRequests = previewRequired != null,
              previewApiBaseUrl = previewRequired?.httpsEndpoint,
              previewToken = previewRequired?.token,
            ),
            null,
          )
          restored += reportedId
        } catch (e: Exception) {
          PasskeyLog.e(CredentialRepository.TAG, "Failed to restore a synced passkey", e)
          skipped += mapOf("credentialId" to reportedId, "reason" to "error")
        }
      }

      mapOf("restored" to restored, "skipped" to skipped)
    }

    // The iOS AutoFill identity store (ASCredentialIdentityStore) has no
    // Android analogue: our CredentialProviderService answers each
    // BeginGetCredentialRequest from MMKV on demand, so there is no store to
    // pre-populate. This is a no-op purely to satisfy the shared JS API.
    AsyncFunction("refreshCredentialIdentities") {
      // no-op on Android
    }
  }

  /**
   * Returns `true` when this app's [PasskeyAutofillCredentialProviderService]
   * is registered as an active credential provider for the current user.
   *
   * On API 34+ (UpsideDownCake) we use the official
   * [android.credentials.CredentialManager.isEnabledCredentialProviderService]
   * API, which reflects the user's current toggle in Settings in real time.
   *
   * On older devices we fall back to a best-effort read of the `@hide`
   * `credential_service` / `credential_service_primary` Secure settings. These
   * typically throw `SecurityException` for non-system apps on Android 12+,
   * in which case we conservatively return `false` rather than guess.
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
    val component = ComponentName(
      context.packageName,
      PasskeyAutofillCredentialProviderService::class.java.name,
    )
    val expected = component.flattenToString()

    // Preferred path (API 34+, UpsideDownCake): ask the platform
    // `CredentialManager` system service whether our component is enabled.
    // This is the official, real-time-accurate signal and is trusted
    // exclusively on supported OS versions.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      return try {
        val cm = context.getSystemService(android.credentials.CredentialManager::class.java)
        cm != null && cm.isEnabledCredentialProviderService(component)
      } catch (e: Throwable) {
        PasskeyLog.d("ReactNativePasskeyAutofill", "CredentialManager.isEnabledCredentialProviderService failed: ${e.message}")
        false
      }
    }

    // Pre-API-34 best-effort: try the (often `@hide`) Secure settings keys.
    val resolver = context.contentResolver
    val keys = arrayOf("credential_service", "credential_service_primary")
    for (key in keys) {
      val value = try {
        Settings.Secure.getString(resolver, key)
      } catch (e: SecurityException) {
        PasskeyLog.d("ReactNativePasskeyAutofill", "Secure key $key not readable: ${e.message}")
        null
      } ?: continue
      if (value.isEmpty()) continue
      val enabled = value.split(':').any { it.equals(expected, ignoreCase = true) } ||
        value.contains(expected, ignoreCase = true)
      if (enabled) return true
    }
    return false
  }

  /**
   * Best-effort deep link into the user's credential-provider preferences so
   * they can toggle our service on. Falls back to the app-details page when
   * the credential provider screen is not available on the device.
   */
  private fun openCredentialProviderSettings(context: Context): Boolean {
    // The system action for the Credential Manager provider picker is
    // `android.settings.CREDENTIAL_PROVIDER` (`Settings.ACTION_CREDENTIAL_PROVIDER`,
    // API 34+). Some OEM Settings builds additionally accept a
    // `:settings:fragment_args_key` extra so the screen scrolls directly to
    // our app's row instead of the generic list. We also include a legacy
    // autofill-service picker fallback for devices where the Credential
    // Manager screen isn't a directly launchable activity.
    val component = ComponentName(
      context.packageName,
      PasskeyAutofillCredentialProviderService::class.java.name,
    ).flattenToString()
    val intents = listOf(
      // Preferred: Credential Manager provider settings, deep-linked to our row.
      Intent("android.settings.CREDENTIAL_PROVIDER").apply {
        putExtra(":settings:fragment_args_key", component)
        putExtra(
          ":settings:show_fragment_args",
          android.os.Bundle().apply { putString(":settings:fragment_args_key", component) },
        )
      },
      // Same screen without the deep-link extras (some OEMs ignore them).
      Intent("android.settings.CREDENTIAL_PROVIDER"),
      // Legacy / fallback: the system autofill provider picker, which on
      // pre-14 devices is the closest "pick a passkey provider" screen.
      Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).apply {
        data = Uri.parse("package:${context.packageName}")
      },
      // Last-resort fallback: this app's details page.
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
        PasskeyLog.w("ReactNativePasskeyAutofill", "Failed to open ${intent.action}: ${e.message}")
      }
    }
    return false
  }
}
