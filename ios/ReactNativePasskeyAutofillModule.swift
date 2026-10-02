import ExpoModulesCore
import AuthenticationServices
#if canImport(UIKit)
import UIKit
#endif

public class ReactNativePasskeyAutofillModule: Module {
  // Each module class must implement the definition function. The definition consists of components
  // that describes the module's functionality and behavior.
  // See https://docs.expo.dev/modules/module-api for more details about available components.
  public func definition() -> ModuleDefinition {
    // Sets the name of the module that JavaScript code will use to refer to the module. Takes a string as an argument.
    // Can be inferred from module's class name, but it's recommended to set it explicitly for clarity.
    // The module will be accessible from `requireNativeModule('ReactNativePasskeyAutofill')` in JavaScript.
    Name("ReactNativePasskeyAutofill")

    Events("onPasskeyAdded", "onPasskeyAuthenticated")

    AsyncFunction("setMasterKey") { (secret: Data) in
      guard let store = PasskeyCredentialStore() else {
        throw NSError(
          domain: "ReactNativePasskeyAutofill",
          code: 1,
          userInfo: [NSLocalizedDescriptionKey: "App Group is not configured for passkey autofill."]
        )
      }
      store.saveMasterKey(secret)
    }

    // Points the passkey hierarchy at the wallet's deterministic-P256 main key.
    // The scheme is not a parameter: it is read from the record's own metadata, so
    // a wallet cannot mislabel which hierarchy it handed us.
    AsyncFunction("setMainKeyId") { (id: String) in
      guard let store = PasskeyCredentialStore() else {
        throw NSError(
          domain: "ReactNativePasskeyAutofill",
          code: 1,
          userInfo: [NSLocalizedDescriptionKey: "App Group is not configured for passkey autofill."]
        )
      }
      store.saveMainKeyId(id)
    }

    // Akita: shares the wallet's HD root secret directly. New passkeys derive
    // from it (scheme `akita-hd-root`); it is kept in the shared Keychain group.
    AsyncFunction("setHdRootSecret") { (secret: Data) in
      guard let store = PasskeyCredentialStore() else {
        throw NSError(
          domain: "ReactNativePasskeyAutofill",
          code: 1,
          userInfo: [NSLocalizedDescriptionKey: "App Group is not configured for passkey autofill."]
        )
      }
      try store.saveHdRootSecret(secret)
    }

    AsyncFunction("getMainKeyId") { () -> String? in
      guard let store = PasskeyCredentialStore() else {
        return nil
      }
      return store.mainKeyId()
    }

    // Deprecated aliases of the two above, kept because installed wallets still
    // call them. They address the same slot — see `saveMainKeyId`.
    AsyncFunction("setHdRootKeyId") { (id: String) in
      guard let store = PasskeyCredentialStore() else {
        throw NSError(
          domain: "ReactNativePasskeyAutofill",
          code: 1,
          userInfo: [NSLocalizedDescriptionKey: "App Group is not configured for passkey autofill."]
        )
      }
      store.saveMainKeyId(id)
    }

    AsyncFunction("getHdRootKeyId") { () -> String? in
      guard let store = PasskeyCredentialStore() else {
        return nil
      }
      return store.mainKeyId()
    }

    AsyncFunction("clearCredentials") {
      guard let store = PasskeyCredentialStore() else {
        return
      }
      store.clear()
      try await store.removeAllIdentities()
    }

    AsyncFunction("deleteCredential") { (credentialId: String) in
      guard let store = PasskeyCredentialStore() else {
        return
      }
      try store.removeCredential(id: credentialId)
      try await store.replaceIdentityStore()
    }

    // Akita: credential-scoped native transaction preview.
    AsyncFunction("configureCredentialTransactionPreview") {
      (credentialId: String, enabled: Bool, apiBaseUrl: String, token: String) in
      guard let store = PasskeyCredentialStore() else {
        throw NSError(
          domain: "ReactNativePasskeyAutofill",
          code: 2,
          userInfo: [NSLocalizedDescriptionKey: "App Group is not configured for passkey autofill."]
        )
      }
      try store.configureTransactionPreview(
        credentialId: credentialId,
        enabled: enabled,
        apiBaseUrl: apiBaseUrl,
        token: token
      )
    }

    AsyncFunction("configureIntentActions") { (getPasskeyAction: String, createPasskeyAction: String) in
      guard let store = PasskeyCredentialStore() else {
        return
      }
      store.configureIntentActions(
        getPasskeyAction: getPasskeyAction,
        createPasskeyAction: createPasskeyAction
      )
    }

    AsyncFunction("replaceCredentialIdentities") { (credentials: [[String: Any]]) in
      guard let store = PasskeyCredentialStore() else {
        throw NSError(
          domain: "ReactNativePasskeyAutofill",
          code: 1,
          userInfo: [NSLocalizedDescriptionKey: "App Group is not configured for passkey autofill."]
        )
      }

      let storedCredentials = credentials.compactMap { credential -> StoredPasskeyCredential? in
        guard let credentialId = credential["credentialId"] as? String ?? credential["id"] as? String,
              let relyingPartyIdentifier =
                credential["relyingPartyIdentifier"] as? String ??
                credential["rpId"] as? String ??
                credential["origin"] as? String,
              let userName =
                credential["userName"] as? String ??
                credential["name"] as? String ??
                credential["userHandle"] as? String,
              let userHandle =
                credential["userHandle"] as? String ??
                credential["userId"] as? String,
              let privateKey =
                credential["privateKey"] as? String ??
                credential["privateKeyBase64"] as? String
        else {
          return nil
        }

        let metadata = credential["metadata"] as? [String: Any]

        return StoredPasskeyCredential(
          credentialId: credentialId,
          relyingPartyIdentifier: relyingPartyIdentifier.relyingPartyIdentifier,
          userName: userName,
          userHandle: userHandle,
          privateKey: privateKey,
          publicKey: credential["publicKey"] as? String ?? credential["publicKeyBase64"] as? String,
          createdAt: credential["createdAt"] as? Double ?? Date().timeIntervalSince1970,
          lastUsedAt: credential["lastUsedAt"] as? Double ?? metadata?["lastUsedAt"] as? Double,
          parentKeyId: credential["parentKeyId"] as? String ?? metadata?["parentKeyId"] as? String,
          // A wallet inserting a credential it derived itself says which root it
          // used; absent, the credential reads back as pinned to the legacy
          // BIP32-Ed25519 root.
          derivationScheme: credential["derivationScheme"] as? String
            ?? metadata?["scheme"] as? String
        )
      }

      try store.replace(storedCredentials)
      try await store.replaceIdentityStore()
    }

    AsyncFunction("refreshCredentialIdentities") {
      guard let store = PasskeyCredentialStore() else {
        throw NSError(
          domain: "ReactNativePasskeyAutofill",
          code: 1,
          userInfo: [NSLocalizedDescriptionKey: "App Group is not configured for passkey autofill."]
        )
      }

      try await store.replaceIdentityStore()
    }

    AsyncFunction("getStoredCredentials") { () -> [[String: Any]] in
      guard let store = PasskeyCredentialStore() else {
        return []
      }

      return store.allCredentials().map { credential in
        var result: [String: Any] = [
          "credentialId": credential.credentialId,
          "relyingPartyIdentifier": credential.relyingPartyIdentifier,
          "userName": credential.userName,
          "userHandle": credential.userHandle,
          "createdAt": credential.createdAt,
        ]

        if let publicKey = credential.publicKey {
          result["publicKey"] = publicKey
        }
        if let lastUsedAt = credential.lastUsedAt {
          result["lastUsedAt"] = lastUsedAt
        }
        if let parentKeyId = credential.parentKeyId {
          result["parentKeyId"] = parentKeyId
        }
        if let derivationScheme = credential.derivationScheme {
          result["derivationScheme"] = derivationScheme
        }
        result["showTransactionRequests"] = credential.showTransactionRequests ?? false
        if let previewApiBaseUrl = credential.previewApiBaseUrl {
          result["previewApiBaseUrl"] = previewApiBaseUrl
        }
        if let previewToken = credential.previewToken {
          result["previewToken"] = previewToken
        }
        // Platform-independent fields (Android's legacy keys differ in meaning).
        result["rpId"] = credential.relyingPartyIdentifier
        result["userIdBase64Url"] =
          Data(base64Encoded: credential.userHandle)?.base64URLEncodedString() ?? credential.userHandle
        result["userDisplayName"] = credential.userName

        return result
      }
    }

    // Adds synced site passkeys to this device. Each key is re-derived from the
    // wallet's HD root and must reproduce its credential ID; existing credentials
    // are left untouched.
    AsyncFunction("restoreDerivedCredentials") { (credentials: [[String: Any]]) -> [String: Any] in
      guard let store = PasskeyCredentialStore() else {
        throw NSError(
          domain: "ReactNativePasskeyAutofill",
          code: 1,
          userInfo: [NSLocalizedDescriptionKey: "App Group is not configured for passkey autofill."]
        )
      }
      // Only the HD root shared through `setHdRootSecret` can reproduce a synced
      // site passkey; without it (or without the master key) nothing is restored.
      let parent = try store.parentSecret(scheme: PasskeyKeystoreRecords.schemeAkitaHdRoot)
      var restored: [String] = []
      var skipped: [[String: String]] = []

      for credential in credentials {
        let reportedId = credential["credentialId"] as? String ?? ""
        guard let expectedId = Data(base64URLEncoded: reportedId),
              let rpId = credential["rpId"] as? String,
              let userIdBase64Url = credential["userIdBase64Url"] as? String,
              let userId = Data(base64URLEncoded: userIdBase64Url),
              let handle = credential["derivationHandle"] as? String
        else {
          skipped.append(["credentialId": reportedId, "reason": "invalid"])
          continue
        }

        if store.credential(id: expectedId) != nil {
          skipped.append(["credentialId": reportedId, "reason": "exists"])
          continue
        }

        do {
          let key = try SiteCredentialDerivation.privateKey(rootSecret: parent.bytes, rpId: rpId, handle: handle)
          guard SiteCredentialDerivation.credentialId(publicKey: key.publicKey) == expectedId else {
            skipped.append(["credentialId": reportedId, "reason": "mismatch"])
            continue
          }
          let createdAtMillis = (credential["createdAt"] as? NSNumber)?.doubleValue
          try store.save(StoredPasskeyCredential(
            credentialId: expectedId.base64EncodedString(),
            relyingPartyIdentifier: rpId,
            userName: credential["userName"] as? String ?? "",
            userHandle: userId.base64EncodedString(),
            privateKey: key.rawRepresentation.base64EncodedString(),
            publicKey: key.publicKey.derRepresentation.base64EncodedString(),
            createdAt: createdAtMillis.map { $0 / 1000 } ?? Date().timeIntervalSince1970,
            lastUsedAt: nil,
            parentKeyId: parent.keyId,
            derivationScheme: parent.scheme,
            showTransactionRequests: credential["showTransactionRequests"] as? Bool,
            previewApiBaseUrl: credential["previewApiBaseUrl"] as? String,
            previewToken: credential["previewToken"] as? String
          ))
          restored.append(reportedId)
        } catch {
          skipped.append(["credentialId": reportedId, "reason": "error"])
        }
      }

      if !restored.isEmpty {
        // AutoFill may be disabled in Settings; the credentials are stored either way.
        try? await store.replaceIdentityStore()
      }
      return ["restored": restored, "skipped": skipped]
    }

    AsyncFunction("getDiagnostics") { () -> [String] in
      guard let store = PasskeyCredentialStore() else {
        return []
      }
      return store.diagnostics()
    }

    // Returns true when this app is the user-selected AutoFill credential
    // provider. On iOS the Credential Provider extension reports its
    // enablement via `ASCredentialIdentityStore.getState`.
    AsyncFunction("isProviderActive") { (promise: Promise) in
      ASCredentialIdentityStore.shared.getState { state in
        promise.resolve(state.isEnabled)
      }
    }

    // Best-effort deep link to the iOS AutoFill settings screen.
    AsyncFunction("openProviderSettings") { () -> Bool in
      #if canImport(UIKit)
      if let url = URL(string: UIApplication.openSettingsURLString),
         UIApplication.shared.canOpenURL(url) {
        UIApplication.shared.open(url)
        return true
      }
      #endif
      return false
    }

    // Enables the module to be used as a native view. Definition components that are accepted as part of the
    // view definition: Prop, Events.
    View(ReactNativePasskeyAutofillView.self) {
      // Defines a setter for the `url` prop.
      Prop("url") { (view: ReactNativePasskeyAutofillView, url: URL) in
        if view.webView.url != url {
          view.webView.load(URLRequest(url: url))
        }
      }

      Events("onLoad")
    }
  }
}
