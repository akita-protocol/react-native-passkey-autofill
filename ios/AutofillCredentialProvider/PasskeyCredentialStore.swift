import AuthenticationServices
import CryptoKit
import Foundation
import Security

enum PasskeyCredentialStoreError: Error {
  case appGroupUnavailable
  case credentialNotFound
  case credentialEncodingFailed
  case credentialStorageFailed
  /// The wallet has not shared its master key with this process yet.
  case masterKeyUnavailable
  /// No record roots the requested scheme (the wallet never called `setMainKeyId`,
  /// or it holds no key of that scheme).
  case parentKeyUnavailable(String?)
  /// The parent record exists but its material is missing or undecodable.
  case parentMaterialUnavailable(String)
  @available(*, deprecated, message: "Use the three specific parent-secret cases")
  case hdRootKeyUnavailable
  case invalidPrivateKey
  case signingFailed
  /// A record already exists for this credential id (under any alias). Stored
  /// passkeys are never overwritten, so their preview policy cannot be dropped.
  case credentialAlreadyExists
}

/// Derives Akita site passkeys from the wallet's HD root. Used by the AutoFill
/// extension when a site registers a passkey and by the app module when restoring
/// synced passkeys. Android (SiteCredentialDerivation.kt) and the desktop app
/// implement the same rule; test-vectors/site-credential-vectors.json pins it.
///
///   handle = lowercase(user.name), one code point at a time
///   d = SHA-512(root ‖ rpId ‖ handle ‖ BE32(attempt))[0..32], first valid attempt
///
/// user.name (rather than the opaque user.id) is deliberate: it is something a
/// person can supply again during recovery. Passkeys created before this rule
/// (iOS derived from user.id) keep working from their stored keys, and sync
/// records carry the exact handle each passkey used.
enum SiteCredentialDerivation {
  /// Swift's lowercased() maps each code point on its own (no context rules such
  /// as Greek final sigma), which Android and JavaScript reproduce exactly.
  static func handle(forUserName userName: String) -> String {
    userName.lowercased()
  }

  static func privateKey(rootSecret: Data, rpId: String, handle: String) throws -> P256.Signing.PrivateKey {
    var input = Data()
    input.append(rootSecret)
    input.append(contentsOf: rpId.utf8)
    input.append(contentsOf: handle.utf8)

    for attempt in UInt32(0)..<16 {
      var candidateInput = input
      var bigEndianAttempt = attempt.bigEndian
      withUnsafeBytes(of: &bigEndianAttempt) { candidateInput.append(contentsOf: $0) }

      let digest = SHA512.hash(data: candidateInput)
      if let key = try? P256.Signing.PrivateKey(rawRepresentation: Data(digest.prefix(32))) {
        return key
      }
    }

    throw PasskeyCredentialStoreError.invalidPrivateKey
  }

  static func credentialId(publicKey: P256.Signing.PublicKey) -> Data {
    Data(SHA256.hash(data: publicKey.derRepresentation))
  }
}

/// The parent secret a credential's deterministic material hangs off, with the
/// record it came from and the scheme it roots.
struct PasskeyParentSecret {
  let keyId: String
  let scheme: String
  let bytes: Data
}

/// One load of stored credentials plus the ids quarantined for an invalid or
/// conflicting transaction-preview policy. (`StoredPasskeyCredential` itself
/// lives in TransactionPreviewPolicy.swift.)
private struct CredentialLoadResult {
  let credentials: [StoredPasskeyCredential]
  let invalidTransactionPreviewCredentialIds: Set<String>
}

/// The on-disk record format shared with the wallet's
/// `@algorandfoundation/react-native-keystore` MMKV instance.
///
/// The keystore splits every key into two entries: `k/<id>` holds PLAINTEXT
/// `Key` metadata (no material) and `m/<id>` holds the sealed raw material,
/// whose sealed plaintext is exactly `base64(bytes)` rather than a JSON
/// document. Records written before the split are a single entry keyed by the
/// bare id, sealing `base64url(JSON.stringify(KeyData))` — metadata and material
/// together. Both layouts must stay readable.
///
/// Kept byte-for-byte in step with `credentials/KeystoreRecords.kt` on Android.
enum PasskeyKeystoreRecords {
  /// Prefix for plaintext `Key` metadata records.
  static let metadataPrefix = "k/"

  /// Prefix for sealed raw-material records.
  static let materialPrefix = "m/"

  /// The type shared by both roots of the wallet's hierarchy; only the scheme
  /// tells them apart.
  static let typeHdRootKey = "hd-root-key"

  /// The deterministic-P256 main key (PBKDF2-HMAC-SHA512, 64 bytes): the root the
  /// passkey hierarchy is defined against, and the preferred parent for new keys.
  static let schemePbkdf2P256 = "pbkdf2-p256"

  /// The BIP32-Ed25519 account root (96 bytes). Passkeys used to derive from it
  /// because it was the only root a wallet exposed, so credentials created then
  /// stay pinned to it.
  static let schemeBip32Ed25519 = "bip32-ed25519"

  /// Akita: the wallet's HD root secret, handed to the provider directly with
  /// `setHdRootSecret` instead of through a key store record. When the wallet
  /// has shared one, new credentials derive from it and are pinned to this
  /// scheme, so PRF and any re-derivation keep using the same root.
  static let schemeAkitaHdRoot = "akita-hd-root"

  static func metadataKey(_ id: String) -> String { metadataPrefix + id }

  static func materialKey(_ id: String) -> String { materialPrefix + id }

  /// The scheme a decoded root record roots. Records written before the flag
  /// existed have none, and every one of those is a BIP32-Ed25519 root.
  static func scheme(of record: [String: Any]) -> String {
    let metadata = record["metadata"] as? [String: Any]
    if let scheme = metadata?["scheme"] as? String, !scheme.isEmpty { return scheme }
    if let scheme = record["scheme"] as? String, !scheme.isEmpty { return scheme }
    return schemeBip32Ed25519
  }

  /// Picks the parent record to derive from: the one rooting `requestedScheme`,
  /// or — for a new credential, which requests none — the main key if there is
  /// one, falling back to the most authoritative candidate.
  static func selectParentKey(
    candidates: [(keyId: String, scheme: String)],
    requestedScheme: String?
  ) -> (keyId: String, scheme: String)? {
    if let requestedScheme {
      return candidates.first { $0.scheme == requestedScheme }
    }
    return candidates.first { $0.scheme == schemePbkdf2P256 } ?? candidates.first
  }
}

final class PasskeyCredentialStore {
  static let defaultSuiteNameKey = "ReactNativePasskeyAutofillAppGroup"
  static let legacyCredentialKey = "ReactNativePasskeyAutofillCredentials"
  static let defaultCredentialKey = "ReactNativePasskeyAutofillCredentialsV2"
  static let defaultMasterKeyKey = "ReactNativePasskeyAutofillMasterKey"
  /// Points at the record whose material is the passkey parent secret. Its
  /// predecessor `defaultHdRootKeyIdKey` named the wallet's BIP32-Ed25519 root;
  /// the slot was renamed rather than reused so a wallet that still writes the
  /// old one is not mistaken for one that opted into the dp256 main key.
  static let defaultMainKeyIdKey = "ReactNativePasskeyAutofillMainKeyId"
  static let defaultHdRootKeyIdKey = "ReactNativePasskeyAutofillHdRootKeyId"
  /// Akita: Keychain service (and legacy plaintext UserDefaults key) of the HD
  /// root secret shared through `setHdRootSecret`.
  static let defaultHdRootSecretKey = "ReactNativePasskeyAutofillHdRootSecret"
  static let defaultGetPasskeyActionKey = "ReactNativePasskeyAutofillGetPasskeyAction"
  static let defaultCreatePasskeyActionKey = "ReactNativePasskeyAutofillCreatePasskeyAction"
  static let defaultDiagnosticsKey = "ReactNativePasskeyAutofillDiagnostics"
  static let defaultDeletedCredentialIdsKey = "ReactNativePasskeyAutofillDeletedCredentialIds"
  /// Info.plist key holding the keychain access-group *base* (without the team
  /// prefix) shared by the app and the AutoFill extension. Injected by the
  /// config plugin so the module stays team-agnostic.
  static let keychainGroupInfoKey = "ReactNativePasskeyAutofillKeychainGroup"

  private let defaults: UserDefaults
  private let credentialKey: String

  init?(
    suiteName: String? = Bundle.main.object(
      forInfoDictionaryKey: PasskeyCredentialStore.defaultSuiteNameKey
    ) as? String,
    credentialKey: String = PasskeyCredentialStore.defaultCredentialKey
  ) {
    guard let suiteName, let defaults = UserDefaults(suiteName: suiteName) else {
      return nil
    }
    self.defaults = defaults
    self.credentialKey = credentialKey
  }

  /// Every credential this store knows about, METADATA ONLY: `privateKey` is
  /// empty on each. Enumeration runs before the user has picked a credential or
  /// verified anything (the AutoFill list, the identity store), so no private
  /// scalar is copied into an immutable string for records the user may never
  /// select. Load exactly one credential's key afterwards with
  /// ``signingCredential(id:)``.
  ///
  /// Akita: a credential whose transaction-preview policy is malformed, or whose
  /// aliases (the same id in another encoding or in the other store) disagree on
  /// the policy, is quarantined — left out entirely rather than resolved by
  /// enumeration order, so a preview requirement can never silently disappear.
  func allCredentials() -> [StoredPasskeyCredential] {
    migrateLegacyCredentials()
    let keystoreResult = allKeystoreCredentials()
    let legacyResult = allLegacyCredentials()
    return StoredPasskeyCredential.resolveCombinedTransactionPreviewAuthority(
      legacyCredentials: legacyResult.credentials.map { $0.withoutPrivateKey() },
      keystoreCredentials: keystoreResult.credentials,
      invalidCredentialIds: keystoreResult.invalidTransactionPreviewCredentialIds.union(
        legacyResult.invalidTransactionPreviewCredentialIds
      )
    ) { [weak self] credentialId in
      self?.appendDiagnostic(
        "skipping conflicting transaction preview policies for credential: \(credentialId)"
      )
    }.credentials
  }

  private func allLegacyCredentials() -> CredentialLoadResult {
    guard let data = defaults.data(forKey: credentialKey) else {
      return CredentialLoadResult(credentials: [], invalidTransactionPreviewCredentialIds: [])
    }
    let result = StoredPasskeyCredential.decodePersistedArrayRecords(data) { [weak self] credentialId in
      self?.appendDiagnostic("skipping invalid legacy credential: \(credentialId ?? "unknown")")
    }
    return CredentialLoadResult(
      credentials: result.credentials,
      invalidTransactionPreviewCredentialIds: result.invalidCredentialIds
    )
  }

  /// Candidates for a relying party, metadata only (see ``allCredentials()``).
  func credentials(relyingPartyIdentifier: String) -> [StoredPasskeyCredential] {
    allCredentials().filter { $0.relyingPartyIdentifier == relyingPartyIdentifier }
  }

  /// The credential stored under `id`, METADATA ONLY. Reads just that
  /// credential's records (every alias), with the same quarantine rule as
  /// ``allCredentials()``.
  func credential(id: Data) -> StoredPasskeyCredential? {
    resolvedCredential(id: id, includePrivateKey: false)
  }

  /// The credential stored under `id` WITH its private key. This is the only
  /// read that materialises private material, so call it once, after the user
  /// has been verified for the assertion, and let the result go out of scope
  /// as soon as the signature is produced.
  func signingCredential(id: Data) -> StoredPasskeyCredential? {
    resolvedCredential(id: id, includePrivateKey: true)
  }

  /// Every stored record of one credential — each id encoding, in the keystore
  /// and the legacy store — resolved so that a disagreement on the transaction
  /// preview policy yields nothing at all.
  private func resolvedCredential(id: Data, includePrivateKey: Bool) -> StoredPasskeyCredential? {
    migrateLegacyCredentials()
    let candidates = credentialIdCandidates(id.base64EncodedString())
    let keystoreResult = keystoreCredentials(ids: candidates, includePrivateKey: includePrivateKey)
    let legacyResult = allLegacyCredentials()
    let legacyCredentials = legacyResult.credentials
      .filter { candidates.contains($0.credentialId) }
      .map { includePrivateKey ? $0 : $0.withoutPrivateKey() }
    return StoredPasskeyCredential.resolveCombinedTransactionPreviewAuthority(
      legacyCredentials: legacyCredentials,
      keystoreCredentials: keystoreResult.credentials,
      invalidCredentialIds: keystoreResult.invalidTransactionPreviewCredentialIds.union(
        legacyResult.invalidTransactionPreviewCredentialIds
      )
    ) { [weak self] credentialId in
      self?.appendDiagnostic(
        "refusing credential with conflicting transaction preview policies: \(credentialId)"
      )
    }.credentials.first
  }

  /// Whether any record exists for `id` — under any alias, in either store —
  /// regardless of whether it reads back as a usable credential.
  func hasCredentialRecord(id: Data) -> Bool {
    let candidates = credentialIdCandidates(id.base64EncodedString())
    if let appGroup = Bundle.main.object(forInfoDictionaryKey: Self.defaultSuiteNameKey) as? String,
       candidates.contains(where: { (try? PasskeyKeystoreMMKV.string(forKey: $0, appGroup: appGroup)) != nil })
    {
      return true
    }
    guard let data = defaults.data(forKey: credentialKey),
          let entries = (try? JSONSerialization.jsonObject(with: data)) as? [Any]
    else { return false }
    return entries.contains {
      guard let id = ($0 as? [String: Any])?["credentialId"] as? String else { return false }
      return candidates.contains(id)
    }
  }

  /// Stores a NEW passkey as a sealed keystore record — from the AutoFill
  /// extension and from the app process alike (both reach MMKV through the
  /// module's PasskeyKeystoreMMKV bridge). Never writes plaintext: without the
  /// master key it throws. Never overwrites: if any record exists for the id
  /// it throws ``PasskeyCredentialStoreError/credentialAlreadyExists``.
  func save(_ credential: StoredPasskeyCredential) throws {
    migrateLegacyCredentials()
    guard let id = Data(base64URLEncoded: credential.credentialId) ?? Data(base64Encoded: credential.credentialId),
          !hasCredentialRecord(id: id)
    else {
      throw PasskeyCredentialStoreError.credentialAlreadyExists
    }
    try saveKeystoreCredential(credential)
    unmarkCredentialDeleted(id: credential.credentialId)
  }

  /// Akita: maps the native bridge's (required, endpoint, token) triple onto the
  /// closed policy, refusing anything that is not exactly `.never` or a complete
  /// `.required(origin, token)`, and stores it.
  func configureTransactionPreview(
    credentialId: String,
    enabled: Bool,
    apiBaseUrl: String,
    token: String
  ) throws {
    let policy = try TransactionPreviewPolicy.fromNativeConfiguration(
      required: enabled,
      httpsEndpoint: apiBaseUrl,
      token: token
    )
    try configureTransactionPreview(credentialId: credentialId, policy: policy)
  }

  /// Akita: sets the transaction-preview policy on every sealed record of
  /// `credentialId` (each alias), so the records can never disagree afterwards.
  /// Only this module's own keystore passkey records are rewritten, and the
  /// bearer token only ever lands in sealed metadata. Throws if no sealed record
  /// exists.
  func configureTransactionPreview(
    credentialId: String,
    policy: TransactionPreviewPolicy
  ) throws {
    migrateLegacyCredentials()
    let candidates = credentialIdCandidates(credentialId)
    var encryptedUpdates: [(key: String, payload: String)] = []
    let appGroup = Bundle.main.object(forInfoDictionaryKey: Self.defaultSuiteNameKey) as? String
    if let masterKey = masterKey(), let appGroup {
      for candidate in candidates {
        guard let payload = try? PasskeyKeystoreMMKV.string(forKey: candidate, appGroup: appGroup),
              let keyData = try? decodeKeystorePayload(payload, masterKey: masterKey),
              let type = keyData["type"] as? String,
              type == "hd-derived-p256" || type == "xhd-derived-p256"
        else { continue }
        var updated = keyData
        var metadata = keyData["metadata"] as? [String: Any] ?? [:]
        try policy.write(to: &metadata)
        updated["metadata"] = metadata
        let encoded = try encodeKeyData(updated)
        encryptedUpdates.append((candidate, try encryptData(masterKey, encoded)))
      }
    }

    guard !encryptedUpdates.isEmpty, let appGroup else {
      throw PasskeyCredentialStoreError.credentialNotFound
    }

    var firstWriteError: Error?
    for update in encryptedUpdates {
      do {
        try PasskeyKeystoreMMKV.setString(update.payload, forKey: update.key, appGroup: appGroup)
      } catch {
        firstWriteError = firstWriteError ?? error
      }
    }
    if let firstWriteError {
      throw firstWriteError
    }
    // Any legacy copy left after migration is a key-less quarantine entry; it
    // would keep disagreeing with the policy just written, so it goes.
    removeLegacyEntries(ids: candidates)
  }

  func removeCredential(id: String) throws {
    let candidateIds = credentialIdCandidates(id)
    markCredentialsDeleted(ids: candidateIds)
    removeLegacyEntries(ids: candidateIds)

    guard let appGroup = Bundle.main.object(forInfoDictionaryKey: Self.defaultSuiteNameKey) as? String else {
      return
    }

    for candidateId in candidateIds {
      try? PasskeyKeystoreMMKV.removeValue(forKey: candidateId, appGroup: appGroup)
    }
  }

  /// Imports credentials (upstream's `replaceCredentialIdentities`). Each new one
  /// is sealed like ``save(_:)``; one that already exists is left as it is, so an
  /// import can never downgrade its preview policy. Nothing is written in
  /// plaintext any more.
  func replace(_ credentials: [StoredPasskeyCredential]) throws {
    for credential in credentials {
      do {
        try save(credential)
      } catch PasskeyCredentialStoreError.credentialAlreadyExists {
        continue
      }
    }
  }

  // MARK: - Legacy plaintext store (migration only)

  /// Earlier builds wrote passkeys created or restored in the app process to
  /// App Group UserDefaults as plaintext JSON, private key and preview token
  /// included. Seals them into the keystore (one record per credential, policy
  /// preserved) and deletes the plaintext copies; see `LegacyCredentialMigration`
  /// for the rules. Needs the master key; until it is available the entries stay
  /// where they are and nothing new is ever added to them.
  func migrateLegacyCredentials() {
    guard let data = defaults.data(forKey: credentialKey) else { return }
    guard let entries = (try? JSONSerialization.jsonObject(with: data)) as? [Any] else {
      appendDiagnostic("legacy credential store is unreadable; leaving it in place")
      return
    }
    guard masterKey() != nil,
          Bundle.main.object(forInfoDictionaryKey: Self.defaultSuiteNameKey) is String
    else { return }

    let plan = LegacyCredentialMigration.plan(entries: entries) { [self] credentialId in
      sealedState(credentialId: credentialId)
    }
    guard plan.changesLegacyStore else { return }

    for credential in plan.toSeal {
      do {
        try saveKeystoreCredential(credential.withDerivedPublicKey())
        unmarkCredentialDeleted(id: credential.credentialId)
      } catch {
        // Leave the legacy store untouched; the next access retries.
        appendDiagnostic("legacy credential migration failed: \(error.localizedDescription)")
        return
      }
    }
    writeLegacyEntries(plan.remainingEntries)
    appendDiagnostic("migrated \(plan.toSeal.count) legacy credential(s) into the sealed keystore")
  }

  private func sealedState(credentialId: String) -> SealedCredentialState {
    let candidates = credentialIdCandidates(credentialId)
    let result = keystoreCredentials(ids: candidates, includePrivateKey: false)
    if !result.invalidTransactionPreviewCredentialIds.isDisjoint(with: candidates) {
      return .unusable
    }
    guard let first = result.credentials.first else {
      // A record nobody can read is never overwritten.
      guard let appGroup = Bundle.main.object(forInfoDictionaryKey: Self.defaultSuiteNameKey) as? String,
            !candidates.contains(where: { (try? PasskeyKeystoreMMKV.string(forKey: $0, appGroup: appGroup)) != nil })
      else { return .unusable }
      return .absent
    }
    guard result.credentials.allSatisfy({ $0.transactionPreviewPolicy == first.transactionPreviewPolicy }) else {
      return .unusable
    }
    return .present(first.transactionPreviewPolicy)
  }

  private func removeLegacyEntries(ids: Set<String>) {
    guard let data = defaults.data(forKey: credentialKey),
          let entries = (try? JSONSerialization.jsonObject(with: data)) as? [Any]
    else { return }
    let remaining = entries.filter {
      guard let id = ($0 as? [String: Any])?["credentialId"] as? String else { return true }
      return !ids.contains(id)
    }
    if remaining.count != entries.count {
      writeLegacyEntries(remaining)
    }
  }

  private func writeLegacyEntries(_ entries: [Any]) {
    if entries.isEmpty {
      defaults.removeObject(forKey: credentialKey)
    } else if let data = try? JSONSerialization.data(withJSONObject: entries) {
      defaults.set(data, forKey: credentialKey)
    }
  }

  private func allKeystoreCredentials() -> CredentialLoadResult {
    guard let masterKey = masterKey(),
          let appGroup = Bundle.main.object(forInfoDictionaryKey: Self.defaultSuiteNameKey) as? String
    else {
      appendDiagnostic("keystore credentials unavailable: missing master key or app group")
      return CredentialLoadResult(credentials: [], invalidTransactionPreviewCredentialIds: [])
    }

    let keys: [String] = PasskeyKeystoreMMKV.allKeys(forAppGroup: appGroup, error: nil)
    appendDiagnostic("keystore allKeys count: \(keys.count)")
    // Enumeration: the material stays undecoded.
    return keystoreCredentials(keys: keys, masterKey: masterKey, appGroup: appGroup, includePrivateKey: false)
  }

  /// Reads the keystore records stored under `ids` (one credential's aliases)
  /// without scanning the store.
  private func keystoreCredentials(ids: Set<String>, includePrivateKey: Bool) -> CredentialLoadResult {
    guard let masterKey = masterKey(),
          let appGroup = Bundle.main.object(forInfoDictionaryKey: Self.defaultSuiteNameKey) as? String
    else {
      return CredentialLoadResult(credentials: [], invalidTransactionPreviewCredentialIds: [])
    }
    return keystoreCredentials(
      keys: Array(ids),
      masterKey: masterKey,
      appGroup: appGroup,
      includePrivateKey: includePrivateKey
    )
  }

  private func keystoreCredentials(
    keys: [String],
    masterKey: Data,
    appGroup: String,
    includePrivateKey: Bool
  ) -> CredentialLoadResult {
    var credentials: [StoredPasskeyCredential] = []
    var invalidIds: Set<String> = []
    for key in keys {
      guard let payload = try? PasskeyKeystoreMMKV.string(forKey: key, appGroup: appGroup) else {
        continue
      }
      switch keystoreCredential(
        payload: payload, key: key, masterKey: masterKey, includePrivateKey: includePrivateKey
      ) {
      case .credential(let credential):
        credentials.append(credential)
      case .invalidTransactionPreviewPolicy(let id):
        invalidIds.formUnion(credentialIdCandidates(id))
        invalidIds.formUnion(credentialIdCandidates(key))
      case .notACredential:
        continue
      }
    }
    return CredentialLoadResult(credentials: credentials, invalidTransactionPreviewCredentialIds: invalidIds)
  }

  private enum KeystoreCredentialRead {
    case credential(StoredPasskeyCredential)
    /// A passkey record whose preview policy is malformed: quarantined, never
    /// read as `.never`.
    case invalidTransactionPreviewPolicy(id: String)
    case notACredential
  }

  /// Decodes one keystore record into a ``StoredPasskeyCredential``.
  ///
  /// - Parameter includePrivateKey: whether to materialise the private key.
  ///   `false` for enumeration and pre-signing lookups; `true` only for the one
  ///   credential the user selected and was verified for. The record must
  ///   carry material either way — that is what distinguishes a passkey record
  ///   from the wallet's split-layout metadata — but with `false` it is only
  ///   checked for presence, never decoded.
  private func keystoreCredential(
    payload: String,
    key: String,
    masterKey: Data,
    includePrivateKey: Bool
  ) -> KeystoreCredentialRead {
    guard let keyData = try? decodeKeystorePayload(payload, masterKey: masterKey),
          let id = keyData["id"] as? String,
          let publicKey = dataArray(keyData["publicKey"]),
          keyData["privateKey"] != nil
    else {
      appendDiagnostic("skipping keystore key: \(key)")
      return .notACredential
    }

    let transactionPreviewPolicy: TransactionPreviewPolicy
    do {
      transactionPreviewPolicy = try TransactionPreviewPolicy.migratingKeystoreMetadata(from: keyData)
    } catch {
      appendDiagnostic("skipping keystore credential with invalid transaction preview policy: \(id)")
      return .invalidTransactionPreviewPolicy(id: id)
    }

    let privateKey: String
    if includePrivateKey {
      guard let material = dataArray(keyData["privateKey"]) else {
        appendDiagnostic("skipping keystore key with undecodable material: \(key)")
        return .notACredential
      }
      privateKey = material.base64EncodedString()
    } else {
      privateKey = ""
    }

    let metadata = keyData["metadata"] as? [String: Any]
    let origin = metadata?["origin"] as? String ?? keyData["origin"] as? String ?? ""
    let userHandle = metadata?["userHandle"] as? String ?? keyData["userHandle"] as? String ?? ""
    let parentKeyId = metadata?["parentKeyId"] as? String ?? keyData["parentKeyId"] as? String
    guard !origin.isEmpty, !userHandle.isEmpty else {
      appendDiagnostic("skipping keystore credential missing metadata: \(id)")
      return .notACredential
    }
    let rawUserName = metadata?["userName"] as? String ?? keyData["userName"] as? String ?? userHandle

    return .credential(StoredPasskeyCredential(
      credentialId: id,
      relyingPartyIdentifier: origin.relyingPartyIdentifier,
      userName: rawUserName.passkeyDisplayName,
      userHandle: userHandle,
      privateKey: privateKey,
      publicKey: publicKey.base64EncodedString(),
      createdAt: metadata?["createdAt"] as? Double ?? Date().timeIntervalSince1970,
      lastUsedAt: metadata?["lastUsedAt"] as? Double,
      parentKeyId: parentKeyId,
      derivationScheme: metadata?["scheme"] as? String,
      transactionPreviewPolicy: transactionPreviewPolicy
    ))
  }

  /// Seals one passkey record. Available in the extension and the app module:
  /// both reach the shared MMKV through the PasskeyKeystoreMMKV bridge.
  private func saveKeystoreCredential(_ credential: StoredPasskeyCredential) throws {
    guard let appGroup = Bundle.main.object(forInfoDictionaryKey: Self.defaultSuiteNameKey) as? String else {
      throw PasskeyCredentialStoreError.appGroupUnavailable
    }
    guard let masterKey = masterKey() else {
      throw PasskeyCredentialStoreError.masterKeyUnavailable
    }
    guard let privateKey = Data(base64URLEncoded: credential.privateKey) ?? Data(base64Encoded: credential.privateKey),
          let publicKeyString = credential.publicKey,
          let publicKey = Data(base64URLEncoded: publicKeyString) ?? Data(base64Encoded: publicKeyString)
    else {
      throw PasskeyCredentialStoreError.invalidPrivateKey
    }

    var metadata: [String: Any] = [
      "origin": credential.relyingPartyIdentifier,
      "userName": credential.userName.passkeyDisplayName,
      "userHandle": credential.userHandle,
      "userId": credential.userHandle,
      "count": 0,
      "createdAt": credential.createdAt,
      "registered": true,
    ]
    if let lastUsedAt = credential.lastUsedAt {
      metadata["lastUsedAt"] = lastUsedAt
    }
    if let parentKeyId = credential.parentKeyId ?? mainKeyId() {
      metadata["parentKeyId"] = parentKeyId
    }
    // Pin the parent this key was derived from, so a later assertion re-derives
    // against the same root even once the wallet points us at a different one.
    if let derivationScheme = credential.derivationScheme {
      metadata["scheme"] = derivationScheme
    }
    try credential.transactionPreviewPolicy.write(to: &metadata)

    let keyData: [String: Any] = [
      "id": credential.credentialId,
      "type": "hd-derived-p256",
      "algorithm": "P256",
      "extractable": false,
      "keyUsages": ["sign"],
      "name": "Passkey: \(credential.relyingPartyIdentifier)",
      "privateKey": privateKey.byteArray,
      "publicKey": publicKey.byteArray,
      "metadata": metadata,
    ]

    let encoded = try encodeKeyData(keyData)
    let encrypted = try encryptData(masterKey, encoded)
    do {
      try PasskeyKeystoreMMKV.setString(encrypted, forKey: credential.credentialId, appGroup: appGroup)
    } catch {
      throw PasskeyCredentialStoreError.credentialStorageFailed
    }
  }

  func recordCredentialUsage(id: String) {
    guard let masterKey = masterKey(),
          let appGroup = Bundle.main.object(forInfoDictionaryKey: Self.defaultSuiteNameKey) as? String
    else { return }

    for candidate in credentialIdCandidates(id) {
      guard let payload = try? PasskeyKeystoreMMKV.string(forKey: candidate, appGroup: appGroup),
            var keyData = try? decodeKeystorePayload(payload, masterKey: masterKey)
      else { continue }

      var metadata = keyData["metadata"] as? [String: Any] ?? [:]
      metadata["lastUsedAt"] = Date().timeIntervalSince1970
      metadata["count"] = ((metadata["count"] as? Int) ?? 0) + 1
      keyData["metadata"] = metadata

      guard let encoded = try? encodeKeyData(keyData),
            let encrypted = try? encryptData(masterKey, encoded)
      else { return }
      try? PasskeyKeystoreMMKV.setString(encrypted, forKey: candidate, appGroup: appGroup)
      return
    }
  }

  func clear() {
    defaults.removeObject(forKey: credentialKey)
    defaults.removeObject(forKey: Self.legacyCredentialKey)
    defaults.removeObject(forKey: Self.defaultDeletedCredentialIdsKey)
    defaults.removeObject(forKey: Self.defaultMasterKeyKey)
    defaults.removeObject(forKey: Self.defaultMainKeyIdKey)
    defaults.removeObject(forKey: Self.defaultHdRootKeyIdKey)
    defaults.removeObject(forKey: Self.defaultHdRootSecretKey)
    defaults.removeObject(forKey: Self.defaultGetPasskeyActionKey)
    defaults.removeObject(forKey: Self.defaultCreatePasskeyActionKey)
    if let query = masterKeyQuery() {
      _ = SecItemDelete(query as CFDictionary)
    }
    if let query = keychainQuery(service: Self.defaultHdRootSecretKey) {
      _ = SecItemDelete(query as CFDictionary)
    }
  }

  // MARK: - Master key (Keychain-backed)
  //
  // The master key is the KEK for the credential store and is read by *both*
  // the app and the AutoFill extension. It is stored in the Keychain (encrypted
  // at rest, hardware-backed) in a shared access group so both processes can
  // read it — never in plaintext UserDefaults. Accessibility is
  // `AfterFirstUnlockThisDeviceOnly`, NOT biometric: the extension must read the
  // key to *enumerate* credentials before the user authenticates, so a
  // biometric-gated item would break the AutoFill list. Biometric checks stay at
  // the assertion step (`LAContext` in `CredentialProviderViewController`).

  func saveMasterKey(_ secret: Data) {
    guard var query = masterKeyQuery() else { return }
    // Upsert: drop any existing value, then add the new one.
    _ = SecItemDelete(query as CFDictionary)
    query[kSecValueData as String] = secret
    query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    _ = SecItemAdd(query as CFDictionary, nil)
    // Scrub any legacy plaintext copy now that the Keychain holds the key.
    defaults.removeObject(forKey: Self.defaultMasterKeyKey)
  }

  func masterKey() -> Data? {
    if var query = masterKeyQuery() {
      query[kSecReturnData as String] = true
      query[kSecMatchLimit as String] = kSecMatchLimitOne
      var item: CFTypeRef?
      if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
         let data = item as? Data
      {
        return data
      }
    }
    // Migration: older builds stored the key as plaintext in the App Group
    // UserDefaults. Move it into the Keychain (and scrub the plaintext) once.
    if let legacy = defaults.string(forKey: Self.defaultMasterKeyKey),
       let data = Data(base64URLEncoded: legacy) ?? Data(base64Encoded: legacy)
    {
      saveMasterKey(data)
      return data
    }
    return nil
  }

  func isMasterKeyAvailable() -> Bool {
    masterKey() != nil
  }

  /// Base Keychain query identifying the shared master-key item. Returns `nil`
  /// when the access group can't be resolved (no Info.plist group or no team
  /// prefix), in which case the caller falls back / no-ops rather than writing
  /// to the wrong place.
  private func masterKeyQuery() -> [String: Any]? {
    keychainQuery(service: Self.defaultMasterKeyKey)
  }

  /// Base Keychain query for one shared generic-password item in the app/extension
  /// access group, or `nil` when the group can't be resolved.
  private func keychainQuery(service: String) -> [String: Any]? {
    guard let accessGroup = masterKeyAccessGroup() else { return nil }
    return [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: service,
      kSecAttrAccessGroup as String: accessGroup,
    ]
  }

  // MARK: - Akita HD root secret (Keychain-backed)
  //
  // Akita shares its wallet HD root with the provider directly rather than as a
  // key store record. It is a root secret, so it gets the same treatment as the
  // master key: the shared Keychain group, `AfterFirstUnlockThisDeviceOnly`, never
  // plaintext UserDefaults (where builds before this one kept it).

  /// Stores the HD root secret. Fails closed: if the Keychain write cannot be
  /// read back, it throws instead of leaving the wallet believing the root is set.
  func saveHdRootSecret(_ secret: Data) throws {
    guard !secret.isEmpty else {
      throw PasskeyCredentialStoreError.parentMaterialUnavailable(PasskeyKeystoreRecords.schemeAkitaHdRoot)
    }
    guard var query = keychainQuery(service: Self.defaultHdRootSecretKey) else {
      throw PasskeyCredentialStoreError.appGroupUnavailable
    }
    _ = SecItemDelete(query as CFDictionary)
    query[kSecValueData as String] = secret
    query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let status = SecItemAdd(query as CFDictionary, nil)
    defaults.removeObject(forKey: Self.defaultHdRootSecretKey)
    guard status == errSecSuccess, hdRootSecret() == secret else {
      throw PasskeyCredentialStoreError.credentialStorageFailed
    }
  }

  /// The HD root secret the wallet shared with `setHdRootSecret`, if any.
  func hdRootSecret() -> Data? {
    if var query = keychainQuery(service: Self.defaultHdRootSecretKey) {
      query[kSecReturnData as String] = true
      query[kSecMatchLimit as String] = kSecMatchLimitOne
      var item: CFTypeRef?
      if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
         let data = item as? Data,
         !data.isEmpty
      {
        return data
      }
    }
    // Migration: earlier Akita builds kept the root as plaintext base64url in the
    // App Group UserDefaults. Move it into the Keychain and scrub the plaintext.
    if let legacy = defaults.string(forKey: Self.defaultHdRootSecretKey),
       let data = Data(base64URLEncoded: legacy) ?? Data(base64Encoded: legacy),
       !data.isEmpty
    {
      if (try? saveHdRootSecret(data)) == nil {
        appendDiagnostic("could not move the HD root secret into the Keychain")
      }
      return data
    }
    return nil
  }

  /// The full keychain access group (`<TeamID>.<base>`). The base is injected by
  /// the config plugin via Info.plist; the team prefix is resolved at runtime.
  private func masterKeyAccessGroup() -> String? {
    guard
      let base = Bundle.main.object(forInfoDictionaryKey: Self.keychainGroupInfoKey) as? String,
      let prefix = Self.keychainTeamPrefix()
    else {
      return nil
    }
    return prefix + base
  }

  private static var cachedTeamPrefix: String?

  /// Resolves the app's keychain access-group team prefix (`<TeamID>.`) at
  /// runtime by probing a throwaway Keychain item and reading back the group the
  /// system assigns. Avoids hardcoding a team ID in a module shared across teams.
  private static func keychainTeamPrefix() -> String? {
    if let cached = cachedTeamPrefix {
      return cached
    }
    let probeAccount = "ReactNativePasskeyAutofillTeamPrefixProbe"
    let cleanup: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrAccount as String: probeAccount,
    ]
    _ = SecItemDelete(cleanup as CFDictionary)

    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrAccount as String: probeAccount,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      kSecValueData as String: Data(),
      kSecReturnAttributes as String: true,
    ]
    var result: CFTypeRef?
    let status = SecItemAdd(query as CFDictionary, &result)
    defer { _ = SecItemDelete(cleanup as CFDictionary) }

    guard
      status == errSecSuccess,
      let attributes = result as? [String: Any],
      let accessGroup = attributes[kSecAttrAccessGroup as String] as? String,
      let dotIndex = accessGroup.firstIndex(of: ".")
    else {
      return nil
    }
    // accessGroup is "<TeamID>.<something>"; keep through the first dot.
    let prefix = String(accessGroup[...dotIndex])
    cachedTeamPrefix = prefix
    return prefix
  }

  /// Records which key store record the passkey hierarchy derives from — the
  /// wallet's deterministic-P256 main key. The scheme is deliberately not part of
  /// this call: it is read from the record's own metadata, so a wallet cannot
  /// mislabel it.
  func saveMainKeyId(_ id: String) {
    defaults.set(id, forKey: Self.defaultMainKeyIdKey)
  }

  func mainKeyId() -> String? {
    defaults.string(forKey: Self.defaultMainKeyIdKey)
      ?? defaults.string(forKey: Self.defaultHdRootKeyIdKey)
  }

  /// Writes the same slot as `saveMainKeyId`: which setter a wallet happens to
  /// call says nothing about the record.
  @available(*, deprecated, message: "The passkey parent is no longer the BIP32-Ed25519 root")
  func saveHdRootKeyId(_ id: String) {
    saveMainKeyId(id)
  }

  @available(*, deprecated, message: "The passkey parent is no longer the BIP32-Ed25519 root")
  func hdRootKeyId() -> String? {
    mainKeyId()
  }

  /// Resolves the parent secret the deterministic P-256 key and the PRF
  /// `credRandom` are derived from.
  ///
  /// - Parameter scheme: the scheme a credential is pinned to, or `nil` for a new
  ///   credential, which then takes the preferred (dp256 main key) parent.
  func parentSecret(scheme: String? = nil) throws -> PasskeyParentSecret {
    guard let masterKey = masterKey() else {
      throw PasskeyCredentialStoreError.masterKeyUnavailable
    }
    guard let appGroup = Bundle.main.object(forInfoDictionaryKey: Self.defaultSuiteNameKey) as? String
    else {
      throw PasskeyCredentialStoreError.appGroupUnavailable
    }

    // Akita: a root shared through `setHdRootSecret` is the parent for every new
    // credential and for every credential pinned to it.
    if scheme == nil || scheme == PasskeyKeystoreRecords.schemeAkitaHdRoot {
      if let root = hdRootSecret() {
        return PasskeyParentSecret(
          keyId: mainKeyId() ?? PasskeyKeystoreRecords.schemeAkitaHdRoot,
          scheme: PasskeyKeystoreRecords.schemeAkitaHdRoot,
          bytes: root
        )
      }
      if scheme != nil {
        throw PasskeyCredentialStoreError.parentKeyUnavailable(scheme)
      }
    }

    let candidates = parentKeyCandidates(masterKey: masterKey, appGroup: appGroup)
    guard let selected = PasskeyKeystoreRecords.selectParentKey(
      candidates: candidates,
      requestedScheme: scheme
    ) else {
      throw PasskeyCredentialStoreError.parentKeyUnavailable(scheme)
    }
    guard let bytes = material(of: selected.keyId, masterKey: masterKey, appGroup: appGroup) else {
      throw PasskeyCredentialStoreError.parentMaterialUnavailable(selected.keyId)
    }
    return PasskeyParentSecret(keyId: selected.keyId, scheme: selected.scheme, bytes: bytes)
  }

  /// The roots this device could derive from, most authoritative first: what the
  /// wallet pointed us at, then any root record present in the shared store.
  ///
  /// The scan matters for a credential pinned to a scheme the wallet is no longer
  /// pointing at: an already-issued passkey must keep re-deriving from the
  /// BIP32-Ed25519 root even once new keys use the dp256 main key.
  private func parentKeyCandidates(
    masterKey: Data,
    appGroup: String
  ) -> [(keyId: String, scheme: String)] {
    let pointed = [
      defaults.string(forKey: Self.defaultMainKeyIdKey),
      defaults.string(forKey: Self.defaultHdRootKeyIdKey),
    ].compactMap { $0 }

    let discovered = PasskeyKeystoreMMKV.allKeys(forAppGroup: appGroup, error: nil)
      .filter { $0.hasPrefix(PasskeyKeystoreRecords.metadataPrefix) }
      .map { String($0.dropFirst(PasskeyKeystoreRecords.metadataPrefix.count)) }

    var seen = Set<String>()
    var candidates: [(keyId: String, scheme: String)] = []
    for id in pointed + discovered where seen.insert(id).inserted {
      guard let record = metadata(of: id, masterKey: masterKey, appGroup: appGroup) else { continue }
      // A discovered record is only a candidate if it is a root; a record the
      // wallet explicitly pointed at is trusted even if its type predates the
      // current naming.
      if !pointed.contains(id),
         record["type"] as? String != PasskeyKeystoreRecords.typeHdRootKey
      {
        continue
      }
      candidates.append((keyId: id, scheme: PasskeyKeystoreRecords.scheme(of: record)))
    }
    return candidates
  }

  /// A record's metadata, from `k/<id>` (plaintext) or from the sealed legacy flat
  /// record keyed by the bare id.
  private func metadata(of id: String, masterKey: Data, appGroup: String) -> [String: Any]? {
    if let plaintext = try? PasskeyKeystoreMMKV.string(
      forKey: PasskeyKeystoreRecords.metadataKey(id),
      appGroup: appGroup
    ),
      let data = plaintext.data(using: .utf8),
      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    {
      return json
    }
    guard let payload = try? PasskeyKeystoreMMKV.string(forKey: id, appGroup: appGroup) else {
      return nil
    }
    return try? decodeKeystorePayload(payload, masterKey: masterKey)
  }

  /// A record's raw secret bytes, from `m/<id>` (whose sealed plaintext is
  /// `base64(bytes)`) or from the inline material of the legacy flat record.
  private func material(of id: String, masterKey: Data, appGroup: String) -> Data? {
    if let sealed = try? PasskeyKeystoreMMKV.string(
      forKey: PasskeyKeystoreRecords.materialKey(id),
      appGroup: appGroup
    ),
      let encoded = try? decryptData(masterKey, sealed),
      let bytes = Data(base64Encoded: encoded) ?? Data(base64URLEncoded: encoded)
    {
      return bytes
    }

    guard let payload = try? PasskeyKeystoreMMKV.string(forKey: id, appGroup: appGroup),
          let keyData = try? decodeKeystorePayload(payload, masterKey: masterKey)
    else {
      return nil
    }
    if let seed = dataArray(keyData["seed"]) ?? dataArray(keyData["privateKey"]) {
      return seed
    }
    if let seed = keyData["seed"] as? String ?? keyData["privateKey"] as? String {
      return Self.secretStringData(seed)
    }
    return nil
  }

  /// The raw parent secret for a new credential. Prefer ``parentSecret(scheme:)``,
  /// whose failure says which of the three things went wrong.
  func hdRootKeySecret() throws -> Data {
    try parentSecret().bytes
  }

  func configureIntentActions(getPasskeyAction: String, createPasskeyAction: String) {
    defaults.set(getPasskeyAction, forKey: Self.defaultGetPasskeyActionKey)
    defaults.set(createPasskeyAction, forKey: Self.defaultCreatePasskeyActionKey)
  }

  func appendDiagnostic(_ message: String) {
    var diagnostics = defaults.array(forKey: Self.defaultDiagnosticsKey) as? [String] ?? []
    let timestamp = ISO8601DateFormatter().string(from: Date())
    diagnostics.append("\(timestamp) \(message)")
    defaults.set(Array(diagnostics.suffix(50)), forKey: Self.defaultDiagnosticsKey)
  }

  func diagnostics() -> [String] {
    defaults.array(forKey: Self.defaultDiagnosticsKey) as? [String] ?? []
  }

  func isCredentialDeleted(id: Data) -> Bool {
    isCredentialDeleted(id: id.base64EncodedString()) || isCredentialDeleted(id: id.base64URLEncodedString())
  }

  func replaceIdentityStore() async throws {
    guard #available(iOS 17.0, *) else {
      return
    }

    let identities = allCredentials().map { credential in
      ASPasskeyCredentialIdentity(
        relyingPartyIdentifier: credential.relyingPartyIdentifier,
        userName: credential.userName,
        credentialID: Data(base64URLEncoded: credential.credentialId) ?? Data(),
        userHandle: Data(base64URLEncoded: credential.userHandle) ?? Data(credential.userHandle.utf8),
        recordIdentifier: credential.credentialId
      )
    }

    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities) { success, error in
        if let error {
          continuation.resume(throwing: error)
        } else if success {
          continuation.resume()
        } else {
          continuation.resume(throwing: PasskeyCredentialStoreError.credentialNotFound)
        }
      }
    }
  }

  func removeAllIdentities() async throws {
    guard #available(iOS 17.0, *) else {
      return
    }

    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      ASCredentialIdentityStore.shared.removeAllCredentialIdentities { success, error in
        if let error {
          continuation.resume(throwing: error)
        } else if success {
          continuation.resume()
        } else {
          continuation.resume(throwing: PasskeyCredentialStoreError.credentialNotFound)
        }
      }
    }
  }

  private func credentialIdCandidates(_ id: String) -> Set<String> {
    passkeyCredentialIdCandidates(id)
  }

  private func deletedCredentialIds() -> Set<String> {
    Set(defaults.stringArray(forKey: Self.defaultDeletedCredentialIdsKey) ?? [])
  }

  private func isCredentialDeleted(id: String) -> Bool {
    !deletedCredentialIds().isDisjoint(with: credentialIdCandidates(id))
  }

  private func markCredentialsDeleted(ids: Set<String>) {
    var deletedIds = deletedCredentialIds()
    deletedIds.formUnion(ids)
    defaults.set(Array(deletedIds), forKey: Self.defaultDeletedCredentialIdsKey)
  }

  private func unmarkCredentialDeleted(id: String) {
    var deletedIds = deletedCredentialIds()
    deletedIds.subtract(credentialIdCandidates(id))
    defaults.set(Array(deletedIds), forKey: Self.defaultDeletedCredentialIdsKey)
  }

  private func encodeKeyData(_ keyData: [String: Any]) throws -> String {
    let jsonData = try JSONSerialization.data(withJSONObject: keyData, options: [])
    return jsonData.base64URLEncodedString()
  }

  private func decodeKeystorePayload(_ payload: String, masterKey: Data) throws -> [String: Any] {
    let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
    // An envelope is `iv` + `content` (the tag either appended to the content or,
    // in the legacy shape, in its own `tag` field). Anything else that is JSON is
    // an already-decoded record.
    if trimmed.hasPrefix("{"),
       let payloadData = trimmed.data(using: .utf8),
       let json = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any],
       json["iv"] == nil || json["content"] == nil
    {
      return json
    }

    let encoded = trimmed.hasPrefix("{") ? try decryptData(masterKey, trimmed) : trimmed
    guard let jsonData = Data(base64URLEncoded: encoded) ?? encoded.data(using: .utf8),
          let json = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any]
    else {
      throw PasskeyCredentialStoreError.credentialEncodingFailed
    }
    return json
  }

  private func encryptData(_ key: Data, _ plaintext: String) throws -> String {
    let symmetricKey = SymmetricKey(data: key)
    let nonceData = Data((0..<12).map { _ in UInt8.random(in: 0...255) })
    let nonce = try AES.GCM.Nonce(data: nonceData)
    let sealedBox = try AES.GCM.seal(Data(plaintext.utf8), using: symmetricKey, nonce: nonce)

    let payload: [String: String] = [
      "iv": nonceData.base64EncodedString(),
      "tag": sealedBox.tag.base64EncodedString(),
      "content": sealedBox.ciphertext.base64EncodedString(),
    ]
    let data = try JSONSerialization.data(withJSONObject: payload, options: [])
    guard let string = String(data: data, encoding: .utf8) else {
      throw PasskeyCredentialStoreError.credentialEncodingFailed
    }
    return string
  }

  private func decryptData(_ key: Data, _ payload: String) throws -> String {
    guard let payloadData = payload.data(using: .utf8),
          let json = try JSONSerialization.jsonObject(with: payloadData) as? [String: String],
          let ivString = json["iv"], let iv = Data(base64Encoded: ivString),
          let contentString = json["content"], let content = Data(base64Encoded: contentString)
    else {
      throw PasskeyCredentialStoreError.credentialEncodingFailed
    }

    // The keystore's current `sealData` appends the 16-byte GCM tag to the
    // ciphertext (the WebCrypto convention); the legacy envelope carried it in its
    // own field. Both have to open, or existing records become unreadable.
    let ciphertext: Data
    let tag: Data
    if let tagString = json["tag"], let separateTag = Data(base64Encoded: tagString),
       !separateTag.isEmpty
    {
      ciphertext = content
      tag = separateTag
    } else {
      guard content.count > 16 else {
        throw PasskeyCredentialStoreError.credentialEncodingFailed
      }
      ciphertext = content.prefix(content.count - 16)
      tag = content.suffix(16)
    }

    let sealedBox = try AES.GCM.SealedBox(
      nonce: AES.GCM.Nonce(data: iv),
      ciphertext: ciphertext,
      tag: tag
    )
    let decrypted = try AES.GCM.open(sealedBox, using: SymmetricKey(data: key))
    guard let string = String(data: decrypted, encoding: .utf8) else {
      throw PasskeyCredentialStoreError.credentialEncodingFailed
    }
    return string
  }

  private func dataArray(_ value: Any?) -> Data? {
    guard let array = value as? [Any] else {
      return nil
    }
    var data = Data(capacity: array.count)
    for item in array {
      if let int = item as? Int {
        data.append(UInt8(int & 0xff))
      } else if let number = item as? NSNumber {
        data.append(UInt8(truncating: number))
      } else {
        return nil
      }
    }
    return data
  }

  private static func secretStringData(_ secret: String) -> Data? {
    let trimmed = secret.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.hasPrefix("0x") || trimmed.hasPrefix("0X") {
      return Data(hex: String(trimmed.dropFirst(2)))
    }
    return Data(hex: trimmed) ?? Data(base64URLEncoded: trimmed) ?? Data(base64Encoded: trimmed)
  }
}

extension StoredPasskeyCredential {
  var credentialIdData: Data {
    Data(base64URLEncoded: credentialId) ?? Data()
  }

  /// The same record with `publicKey` filled from the private key when an old
  /// legacy entry lacks it (a sealed record needs both).
  func withDerivedPublicKey() throws -> StoredPasskeyCredential {
    if let publicKey, !publicKey.isEmpty { return self }
    guard let keyData = Data(base64URLEncoded: privateKey) ?? Data(base64Encoded: privateKey),
          let key = (try? P256.Signing.PrivateKey(rawRepresentation: keyData))
            ?? (try? P256.Signing.PrivateKey(derRepresentation: keyData))
    else {
      throw PasskeyCredentialStoreError.invalidPrivateKey
    }
    return StoredPasskeyCredential(
      credentialId: credentialId,
      relyingPartyIdentifier: relyingPartyIdentifier,
      userName: userName,
      userHandle: userHandle,
      privateKey: privateKey,
      publicKey: key.publicKey.derRepresentation.base64EncodedString(),
      createdAt: createdAt,
      lastUsedAt: lastUsedAt,
      parentKeyId: parentKeyId,
      derivationScheme: derivationScheme,
      transactionPreviewPolicy: transactionPreviewPolicy
    )
  }

  /// The same record with its private key stripped: what enumeration hands out.
  func withoutPrivateKey() -> StoredPasskeyCredential {
    StoredPasskeyCredential(
      credentialId: credentialId,
      relyingPartyIdentifier: relyingPartyIdentifier,
      userName: userName,
      userHandle: userHandle,
      privateKey: "",
      publicKey: publicKey,
      createdAt: createdAt,
      lastUsedAt: lastUsedAt,
      parentKeyId: parentKeyId,
      derivationScheme: derivationScheme,
      transactionPreviewPolicy: transactionPreviewPolicy
    )
  }

  var userHandleData: Data {
    Data(base64URLEncoded: userHandle) ?? Data(userHandle.utf8)
  }

  func privateSecKey() throws -> SecKey {
    guard let privateKeyData = Data(base64URLEncoded: privateKey) ?? Data(base64Encoded: privateKey)
    else {
      throw PasskeyCredentialStoreError.invalidPrivateKey
    }

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecAttrKeySizeInBits as String: 256,
    ]

    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(privateKeyData as CFData, attributes as CFDictionary, &error)
    else {
      throw error?.takeRetainedValue() ?? PasskeyCredentialStoreError.invalidPrivateKey
    }
    return key
  }

  func sign(_ data: Data) throws -> Data {
    if let privateKeyData = Data(base64URLEncoded: privateKey) ?? Data(base64Encoded: privateKey) {
      if let key = try? P256.Signing.PrivateKey(rawRepresentation: privateKeyData) {
        return try key.signature(for: data).derRepresentation
      }

      if let key = try? P256.Signing.PrivateKey(derRepresentation: privateKeyData) {
        return try key.signature(for: data).derRepresentation
      }
    }

    let key = try privateSecKey()
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, data as CFData, &error)
      as Data?
    else {
      throw error?.takeRetainedValue() ?? PasskeyCredentialStoreError.signingFailed
    }
    return signature
  }
}

extension Data {
  var byteArray: [Int] {
    map { Int($0) }
  }

  init?(hex: String) {
    let normalized = hex.trimmingCharacters(in: .whitespacesAndNewlines)
    guard normalized.count % 2 == 0 else {
      return nil
    }

    var bytes = Data(capacity: normalized.count / 2)
    var index = normalized.startIndex
    while index < normalized.endIndex {
      let nextIndex = normalized.index(index, offsetBy: 2)
      guard let byte = UInt8(normalized[index..<nextIndex], radix: 16) else {
        return nil
      }
      bytes.append(byte)
      index = nextIndex
    }
    self = bytes
  }

  init?(base64URLEncoded string: String) {
    var base64 = string.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let remainder = base64.count % 4
    if remainder > 0 {
      base64.append(String(repeating: "=", count: 4 - remainder))
    }
    self.init(base64Encoded: base64)
  }

  func base64URLEncodedString() -> String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}

extension String {
  var relyingPartyIdentifier: String {
    guard let url = URL(string: self), let host = url.host else {
      return self
    }
    return host
  }

  var passkeyDisplayName: String {
    let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty,
          let decodedData = Data(base64URLEncoded: trimmed) ?? Data(base64Encoded: trimmed),
          let decoded = String(data: decodedData, encoding: .utf8)
    else {
      return self
    }

    let normalized = decoded.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !normalized.isEmpty,
          normalized.unicodeScalars.allSatisfy({ $0.value >= 32 && $0.value != 127 })
    else {
      return self
    }

    return normalized
  }
}
