import Foundation

func passkeyCredentialCanonicalId(_ id: String) -> String {
  guard let data = decodePasskeyCredentialId(id) else {
    return id
  }
  return data.base64EncodedString()
    .replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "=", with: "")
}

func passkeyCredentialIdCandidates(_ id: String) -> Set<String> {
  var candidates: Set<String> = [id]
  guard let data = decodePasskeyCredentialId(id) else {
    return candidates
  }
  candidates.insert(data.base64EncodedString())
  candidates.insert(passkeyCredentialCanonicalId(id))
  return candidates
}

private func decodePasskeyCredentialId(_ id: String) -> Data? {
  var base64 = id.replacingOccurrences(of: "-", with: "+")
    .replacingOccurrences(of: "_", with: "/")
  let remainder = base64.count % 4
  if remainder > 0 {
    base64.append(String(repeating: "=", count: 4 - remainder))
  }
  return Data(base64Encoded: base64)
}

enum TransactionPreviewPolicy: Equatable, Codable {
  static let metadataKey = "transactionPreviewPolicy"

  private static let legacyRequiredKey = "showTransactionRequests"
  private static let legacyEndpointKey = "previewApiBaseUrl"
  private static let legacyTokenKey = "previewToken"

  /// Every key a persisted or bridged record may carry the policy under.
  static let persistedKeys: Set<String> = [
    metadataKey, legacyRequiredKey, legacyEndpointKey, legacyTokenKey,
  ]

  case never
  case required(httpsEndpoint: URL, token: String)

  private enum Kind: String, Codable {
    case never
    case required
  }

  private enum CodingKeys: String, CodingKey {
    case kind
    case httpsEndpoint
    case token
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let kind = try container.decode(Kind.self, forKey: .kind)

    switch kind {
    case .never:
      guard !container.contains(.httpsEndpoint), !container.contains(.token) else {
        throw TransactionPreviewPolicyError.unexpectedNeverConfiguration
      }
      self = .never
    case .required:
      self = try Self.validatedRequired(
        httpsEndpoint: container.decode(String.self, forKey: .httpsEndpoint),
        token: container.decode(String.self, forKey: .token)
      )
    }
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)

    switch self {
    case .never:
      try container.encode(Kind.never, forKey: .kind)
    case .required(let httpsEndpoint, let token):
      _ = try Self.validatedRequired(
        httpsEndpoint: httpsEndpoint.absoluteString,
        token: token
      )
      try container.encode(Kind.required, forKey: .kind)
      try container.encode(httpsEndpoint.absoluteString, forKey: .httpsEndpoint)
      try container.encode(token, forKey: .token)
    }
  }

  static func validatedRequired(
    httpsEndpoint rawEndpoint: String,
    token rawToken: String
  ) throws -> TransactionPreviewPolicy {
    let endpoint = rawEndpoint.trimmingCharacters(in: .whitespacesAndNewlines)
    let token = rawToken.trimmingCharacters(in: .whitespacesAndNewlines)
    guard endpoint == rawEndpoint,
          let components = URLComponents(string: endpoint),
          components.scheme?.lowercased() == "https",
          let host = components.host,
          !host.isEmpty,
          components.user == nil,
          components.password == nil,
          components.percentEncodedPath.isEmpty,
          components.query == nil,
          components.fragment == nil,
          components.port.map({ $0 <= 65_535 }) ?? true,
          let url = components.url
    else {
      throw TransactionPreviewPolicyError.invalidHTTPSEndpoint
    }
    guard token == rawToken, !token.isEmpty else {
      throw TransactionPreviewPolicyError.missingToken
    }
    return .required(httpsEndpoint: url, token: token)
  }

  static func fromNativeConfiguration(
    required: Bool,
    httpsEndpoint: String,
    token: String
  ) throws -> TransactionPreviewPolicy {
    if required {
      return try validatedRequired(httpsEndpoint: httpsEndpoint, token: token)
    }
    guard httpsEndpoint.isEmpty, token.isEmpty else {
      throw TransactionPreviewPolicyError.unexpectedNeverConfiguration
    }
    return .never
  }

  static func migratingMetadata(_ metadata: [String: Any]) throws -> TransactionPreviewPolicy {
    let hasCanonicalPolicy = metadata.keys.contains(metadataKey)
    let hasLegacyPolicy = metadata.keys.contains(legacyRequiredKey) ||
      metadata.keys.contains(legacyEndpointKey) ||
      metadata.keys.contains(legacyTokenKey)

    if hasCanonicalPolicy {
      guard !hasLegacyPolicy,
            let encodedPolicy = metadata[metadataKey] as? [String: Any],
            JSONSerialization.isValidJSONObject(encodedPolicy)
      else {
        throw TransactionPreviewPolicyError.malformedPersistedPolicy
      }
      let data = try JSONSerialization.data(withJSONObject: encodedPolicy)
      return try JSONDecoder().decode(Self.self, from: data)
    }

    return try migrateLegacyTuple(
      required: legacyRequiredValue(metadata: metadata),
      httpsEndpoint: typedLegacyValue(String.self, key: legacyEndpointKey, metadata: metadata),
      token: typedLegacyValue(String.self, key: legacyTokenKey, metadata: metadata),
      requiredPresent: metadata.keys.contains(legacyRequiredKey),
      endpointPresent: metadata.keys.contains(legacyEndpointKey),
      tokenPresent: metadata.keys.contains(legacyTokenKey)
    )
  }

  static func migratingKeystoreMetadata(
    from keyData: [String: Any]
  ) throws -> TransactionPreviewPolicy {
    guard keyData.keys.contains("metadata") else {
      return try migratingMetadata([:])
    }
    guard let metadata = keyData["metadata"] as? [String: Any] else {
      throw TransactionPreviewPolicyError.malformedPersistedPolicy
    }
    return try migratingMetadata(metadata)
  }

  /// The policy as plain JSON values (`{"kind": "never"}` or
  /// `{"kind": "required", "httpsEndpoint": …, "token": …}`), the shape the JS API uses.
  func jsonObject() throws -> [String: Any] {
    let data = try JSONEncoder().encode(self)
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw TransactionPreviewPolicyError.malformedPersistedPolicy
    }
    return object
  }

  func write(to metadata: inout [String: Any]) throws {
    let data = try JSONEncoder().encode(self)
    guard let encodedPolicy = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw TransactionPreviewPolicyError.malformedPersistedPolicy
    }
    metadata[Self.metadataKey] = encodedPolicy
    metadata.removeValue(forKey: Self.legacyRequiredKey)
    metadata.removeValue(forKey: Self.legacyEndpointKey)
    metadata.removeValue(forKey: Self.legacyTokenKey)
  }

  static func migrateLegacyTuple(
    required: Bool?,
    httpsEndpoint: String?,
    token: String?,
    requiredPresent: Bool,
    endpointPresent: Bool,
    tokenPresent: Bool
  ) throws -> TransactionPreviewPolicy {
    guard requiredPresent || endpointPresent || tokenPresent else {
      return .never
    }
    guard requiredPresent, let required else {
      throw TransactionPreviewPolicyError.malformedLegacyPolicy
    }
    if !required {
      guard !endpointPresent, !tokenPresent else {
        throw TransactionPreviewPolicyError.malformedLegacyPolicy
      }
      return .never
    }
    guard endpointPresent,
          tokenPresent,
          let httpsEndpoint,
          let token
    else {
      throw TransactionPreviewPolicyError.malformedLegacyPolicy
    }
    return try validatedRequired(httpsEndpoint: httpsEndpoint, token: token)
  }

  private static func legacyRequiredValue(metadata: [String: Any]) throws -> Bool? {
    guard metadata.keys.contains(legacyRequiredKey) else {
      return nil
    }
    guard let number = metadata[legacyRequiredKey] as? NSNumber,
          CFGetTypeID(number) == CFBooleanGetTypeID()
    else {
      throw TransactionPreviewPolicyError.malformedLegacyPolicy
    }
    return number.boolValue
  }

  private static func typedLegacyValue<T>(
    _ type: T.Type,
    key: String,
    metadata: [String: Any]
  ) throws -> T? {
    guard metadata.keys.contains(key) else {
      return nil
    }
    guard let value = metadata[key] as? T else {
      throw TransactionPreviewPolicyError.malformedLegacyPolicy
    }
    return value
  }
}

enum TransactionPreviewPolicyError: LocalizedError {
  case invalidHTTPSEndpoint
  case missingToken
  case unexpectedNeverConfiguration
  case malformedLegacyPolicy
  case malformedPersistedPolicy

  var errorDescription: String? {
    switch self {
    case .invalidHTTPSEndpoint:
      return "Transaction preview requires a valid HTTPS endpoint."
    case .missingToken:
      return "Transaction preview requires a non-empty token."
    case .unexpectedNeverConfiguration:
      return "Disabled transaction preview cannot include an endpoint or token."
    case .malformedLegacyPolicy:
      return "The legacy transaction preview policy is incomplete."
    case .malformedPersistedPolicy:
      return "The persisted transaction preview policy is malformed."
    }
  }
}

/// One passkey as the provider stores and reads it. Every read except
/// `PasskeyCredentialStore.signingCredential(id:)` leaves `privateKey` empty
/// (metadata-only enumeration); the transaction-preview policy is metadata and
/// is always present, decoded fail-closed.
struct StoredPasskeyCredential: Codable {
  let credentialId: String
  let relyingPartyIdentifier: String
  let userName: String
  let userHandle: String
  /// Base64 private material, or `""` when the record was read without it.
  let privateKey: String
  let publicKey: String?
  let createdAt: Double
  let lastUsedAt: Double?
  let parentKeyId: String?
  /// The derivation scheme this credential is pinned to for life (see
  /// `PasskeyKeystoreRecords`). `nil` predates the field.
  let derivationScheme: String?
  let transactionPreviewPolicy: TransactionPreviewPolicy

  init(
    credentialId: String,
    relyingPartyIdentifier: String,
    userName: String,
    userHandle: String,
    privateKey: String,
    publicKey: String?,
    createdAt: Double,
    lastUsedAt: Double? = nil,
    parentKeyId: String?,
    derivationScheme: String? = nil,
    transactionPreviewPolicy: TransactionPreviewPolicy = .never
  ) {
    self.credentialId = credentialId
    self.relyingPartyIdentifier = relyingPartyIdentifier
    self.userName = userName
    self.userHandle = userHandle
    self.privateKey = privateKey
    self.publicKey = publicKey
    self.createdAt = createdAt
    self.lastUsedAt = lastUsedAt
    self.parentKeyId = parentKeyId
    self.derivationScheme = derivationScheme
    self.transactionPreviewPolicy = transactionPreviewPolicy
  }

  private enum CodingKeys: String, CodingKey {
    case credentialId
    case relyingPartyIdentifier
    case userName
    case userHandle
    case privateKey
    case publicKey
    case createdAt
    case lastUsedAt
    case parentKeyId
    case derivationScheme
    case transactionPreviewPolicy
    case showTransactionRequests
    case previewApiBaseUrl
    case previewToken
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    credentialId = try container.decode(String.self, forKey: .credentialId)
    relyingPartyIdentifier = try container.decode(String.self, forKey: .relyingPartyIdentifier)
    userName = try container.decode(String.self, forKey: .userName)
    userHandle = try container.decode(String.self, forKey: .userHandle)
    privateKey = try container.decode(String.self, forKey: .privateKey)
    publicKey = try container.decodeIfPresent(String.self, forKey: .publicKey)
    createdAt = try container.decode(Double.self, forKey: .createdAt)
    lastUsedAt = try container.decodeIfPresent(Double.self, forKey: .lastUsedAt)
    parentKeyId = try container.decodeIfPresent(String.self, forKey: .parentKeyId)
    derivationScheme = try container.decodeIfPresent(String.self, forKey: .derivationScheme)

    let hasLegacyPolicy = container.contains(.showTransactionRequests) ||
      container.contains(.previewApiBaseUrl) ||
      container.contains(.previewToken)
    if container.contains(.transactionPreviewPolicy) {
      guard !hasLegacyPolicy else {
        throw TransactionPreviewPolicyError.malformedPersistedPolicy
      }
      transactionPreviewPolicy = try container.decode(
        TransactionPreviewPolicy.self,
        forKey: .transactionPreviewPolicy
      )
    } else {
      transactionPreviewPolicy = try TransactionPreviewPolicy.migrateLegacyTuple(
        required: container.decodeIfPresent(Bool.self, forKey: .showTransactionRequests),
        httpsEndpoint: container.decodeIfPresent(String.self, forKey: .previewApiBaseUrl),
        token: container.decodeIfPresent(String.self, forKey: .previewToken),
        requiredPresent: container.contains(.showTransactionRequests),
        endpointPresent: container.contains(.previewApiBaseUrl),
        tokenPresent: container.contains(.previewToken)
      )
    }
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(credentialId, forKey: .credentialId)
    try container.encode(relyingPartyIdentifier, forKey: .relyingPartyIdentifier)
    try container.encode(userName, forKey: .userName)
    try container.encode(userHandle, forKey: .userHandle)
    try container.encode(privateKey, forKey: .privateKey)
    try container.encodeIfPresent(publicKey, forKey: .publicKey)
    try container.encode(createdAt, forKey: .createdAt)
    try container.encodeIfPresent(lastUsedAt, forKey: .lastUsedAt)
    try container.encodeIfPresent(parentKeyId, forKey: .parentKeyId)
    try container.encodeIfPresent(derivationScheme, forKey: .derivationScheme)
    try container.encode(transactionPreviewPolicy, forKey: .transactionPreviewPolicy)
  }

  static func decodePersistedArray(
    _ data: Data,
    onInvalidCredential: ((String?) -> Void)? = nil
  ) -> [StoredPasskeyCredential] {
    decodePersistedArrayResult(
      data,
      onInvalidCredential: onInvalidCredential
    ).credentials
  }

  static func decodePersistedArrayResult(
    _ data: Data,
    onInvalidCredential: ((String?) -> Void)? = nil
  ) -> (
    credentials: [StoredPasskeyCredential],
    invalidCredentialIds: Set<String>
  ) {
    let decoded = decodePersistedArrayRecords(
      data,
      onInvalidCredential: onInvalidCredential
    )
    return resolveTransactionPreviewAuthority(
      credentials: decoded.credentials,
      invalidCredentialIds: decoded.invalidCredentialIds,
      onConflictingCredential: { onInvalidCredential?($0) }
    )
  }

  static func decodePersistedArrayRecords(
    _ data: Data,
    onInvalidCredential: ((String?) -> Void)? = nil
  ) -> (
    credentials: [StoredPasskeyCredential],
    invalidCredentialIds: Set<String>
  ) {
    guard let decodedValues = try? JSONSerialization.jsonObject(with: data),
          let persistedValues = decodedValues as? [Any]
    else {
      onInvalidCredential?(nil)
      return ([], [])
    }

    var decodedCredentials: [StoredPasskeyCredential] = []
    var invalidCredentialIds: Set<String> = []
    for value in persistedValues {
      guard let persistedCredential = value as? [String: Any],
            JSONSerialization.isValidJSONObject(persistedCredential),
            let encodedCredential = try? JSONSerialization.data(withJSONObject: persistedCredential)
      else {
        onInvalidCredential?(nil)
        continue
      }
      do {
        decodedCredentials.append(
          try JSONDecoder().decode(StoredPasskeyCredential.self, from: encodedCredential)
        )
      } catch {
        let credentialId = persistedCredential["credentialId"] as? String
        if let credentialId {
          invalidCredentialIds.formUnion(passkeyCredentialIdCandidates(credentialId))
        }
        onInvalidCredential?(credentialId)
      }
    }

    return (decodedCredentials, invalidCredentialIds)
  }

  static func resolveCombinedTransactionPreviewAuthority(
    legacyCredentials: [StoredPasskeyCredential],
    keystoreCredentials: [StoredPasskeyCredential],
    invalidCredentialIds: Set<String> = [],
    onConflictingCredential: ((String) -> Void)? = nil
  ) -> (
    credentials: [StoredPasskeyCredential],
    invalidCredentialIds: Set<String>
  ) {
    let agreement = resolveTransactionPreviewAuthority(
      credentials: legacyCredentials + keystoreCredentials,
      invalidCredentialIds: invalidCredentialIds,
      onConflictingCredential: onConflictingCredential
    )
    let allowedCanonicalIds = Set(agreement.credentials.map {
      passkeyCredentialCanonicalId($0.credentialId)
    })
    var credentialsByCanonicalId: [String: StoredPasskeyCredential] = [:]

    for credential in legacyCredentials {
      let canonicalId = passkeyCredentialCanonicalId(credential.credentialId)
      guard allowedCanonicalIds.contains(canonicalId) else { continue }
      credentialsByCanonicalId[canonicalId] = credential
    }
    for credential in keystoreCredentials {
      let canonicalId = passkeyCredentialCanonicalId(credential.credentialId)
      guard allowedCanonicalIds.contains(canonicalId) else { continue }
      credentialsByCanonicalId[canonicalId] = credential
    }

    return (Array(credentialsByCanonicalId.values), agreement.invalidCredentialIds)
  }

  static func resolveTransactionPreviewAuthority(
    credentials: [StoredPasskeyCredential],
    invalidCredentialIds initialInvalidCredentialIds: Set<String> = [],
    onConflictingCredential: ((String) -> Void)? = nil
  ) -> (
    credentials: [StoredPasskeyCredential],
    invalidCredentialIds: Set<String>
  ) {
    var invalidCredentialIds = initialInvalidCredentialIds
    let eligibleCredentials = credentials.filter {
      invalidCredentialIds.isDisjoint(with: passkeyCredentialIdCandidates($0.credentialId))
    }
    let credentialGroups = Dictionary(
      grouping: eligibleCredentials,
      by: { passkeyCredentialCanonicalId($0.credentialId) }
    )
    var resolvedCredentials: [StoredPasskeyCredential] = []

    for group in credentialGroups.values {
      guard let first = group.first else { continue }
      guard group.dropFirst().allSatisfy({
        $0.transactionPreviewPolicy == first.transactionPreviewPolicy
      }) else {
        for credential in group {
          invalidCredentialIds.formUnion(passkeyCredentialIdCandidates(credential.credentialId))
        }
        onConflictingCredential?(first.credentialId)
        continue
      }
      resolvedCredentials.append(first)
    }

    return (resolvedCredentials, invalidCredentialIds)
  }
}
