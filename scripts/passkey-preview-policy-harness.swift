import Foundation

@main
struct PasskeyPreviewPolicyHarness {
  static func main() throws {
    guard CommandLine.arguments.count == 2 else {
      throw HarnessError("expected the credential-provider controller source path")
    }

    try assertNever(TransactionPreviewPolicy.migratingMetadata([:]), "missing legacy tuple")
    try assertNever(
      TransactionPreviewPolicy.migratingMetadata(["showTransactionRequests": false]),
      "legacy disabled tuple"
    )

    let legacyRequired = try TransactionPreviewPolicy.migratingMetadata([
      "showTransactionRequests": true,
      "previewApiBaseUrl": "https://preview.akita.example",
      "previewToken": "preview-token",
    ])
    try assertRequired(
      legacyRequired,
      endpoint: "https://preview.akita.example",
      token: "preview-token",
      name: "complete legacy required tuple"
    )
    let decodedLegacyMetadata = try JSONSerialization.jsonObject(
      with: Data(
        """
        {
          "showTransactionRequests": true,
          "previewApiBaseUrl": "https://preview.akita.example",
          "previewToken": "preview-token"
        }
        """.utf8
      )
    ) as? [String: Any]
    guard let decodedLegacyMetadata else {
      throw HarnessError("legacy JSON did not decode to metadata")
    }
    try assertRequired(
      TransactionPreviewPolicy.migratingMetadata(decodedLegacyMetadata),
      endpoint: "https://preview.akita.example",
      token: "preview-token",
      name: "JSON-decoded legacy required tuple"
    )

    try expectFailure("legacy required flag without endpoint or token") {
      _ = try TransactionPreviewPolicy.migratingMetadata([
        "showTransactionRequests": true,
      ])
    }
    try expectFailure("legacy required flag without token") {
      _ = try TransactionPreviewPolicy.migratingMetadata([
        "showTransactionRequests": true,
        "previewApiBaseUrl": "https://preview.akita.example",
      ])
    }
    try expectFailure("legacy required flag with HTTP endpoint") {
      _ = try TransactionPreviewPolicy.migratingMetadata([
        "showTransactionRequests": true,
        "previewApiBaseUrl": "http://preview.akita.example",
        "previewToken": "preview-token",
      ])
    }
    try expectFailure("legacy required flag with invalid HTTPS port") {
      _ = try TransactionPreviewPolicy.migratingMetadata([
        "showTransactionRequests": true,
        "previewApiBaseUrl": "https://preview.akita.example:99999",
        "previewToken": "preview-token",
      ])
    }
    for invalidOrigin in [
      "https://preview.akita.example/",
      "https://preview.akita.example/v1",
      "https://preview.akita.example?tenant=akita",
      "https://preview.akita.example#preview",
    ] {
      try expectFailure("required endpoint is not an exact HTTPS origin: \(invalidOrigin)") {
        _ = try TransactionPreviewPolicy.validatedRequired(
          httpsEndpoint: invalidOrigin,
          token: "preview-token"
        )
      }
    }
    try expectFailure("numeric legacy required flag") {
      let numericFlag = try JSONSerialization.jsonObject(
        with: Data(
          """
          {
            "showTransactionRequests": 1,
            "previewApiBaseUrl": "https://preview.akita.example",
            "previewToken": "preview-token"
          }
          """.utf8
        )
      ) as? [String: Any]
      guard let numericFlag else {
        throw HarnessError("numeric legacy tuple did not decode")
      }
      _ = try TransactionPreviewPolicy.migratingMetadata(numericFlag)
    }
    try expectFailure("legacy disabled tuple with stale token") {
      _ = try TransactionPreviewPolicy.migratingMetadata([
        "showTransactionRequests": false,
        "previewToken": "stale-token",
      ])
    }

    var metadata: [String: Any] = [
      "showTransactionRequests": true,
      "previewApiBaseUrl": "https://legacy.akita.example",
      "previewToken": "legacy-token",
    ]
    let required = try TransactionPreviewPolicy.validatedRequired(
      httpsEndpoint: "https://preview.akita.example",
      token: "preview-token"
    )
    try required.write(to: &metadata)
    guard metadata["showTransactionRequests"] == nil,
          metadata["previewApiBaseUrl"] == nil,
          metadata["previewToken"] == nil,
          metadata[TransactionPreviewPolicy.metadataKey] != nil
    else {
      throw HarnessError("canonical write retained independent legacy fields")
    }
    try assertRequired(
      TransactionPreviewPolicy.migratingMetadata(metadata),
      endpoint: "https://preview.akita.example",
      token: "preview-token",
      name: "canonical metadata round trip"
    )

    try expectFailure("canonical required policy without token") {
      _ = try TransactionPreviewPolicy.migratingMetadata([
        TransactionPreviewPolicy.metadataKey: [
          "kind": "required",
          "httpsEndpoint": "https://preview.akita.example",
        ],
      ])
    }
    try assertNever(
      TransactionPreviewPolicy.migratingKeystoreMetadata(from: [:]),
      "absent keystore metadata"
    )
    try expectFailure("wrong-typed keystore metadata container") {
      _ = try TransactionPreviewPolicy.migratingKeystoreMetadata(from: [
        "metadata": "not-a-metadata-object",
      ])
    }
    try expectFailure("native never mapping with stale configuration") {
      _ = try TransactionPreviewPolicy.fromNativeConfiguration(
        required: false,
        httpsEndpoint: "https://preview.akita.example",
        token: ""
      )
    }

    let encoded = try JSONEncoder().encode(required)
    let decoded = try JSONDecoder().decode(TransactionPreviewPolicy.self, from: encoded)
    guard decoded == required else {
      throw HarnessError("Codable policy round trip changed the policy")
    }

    let credentialFields: [String: Any] = [
      "credentialId": "credential-id",
      "relyingPartyIdentifier": "example.com",
      "userName": "Akita",
      "userHandle": "user-handle",
      "privateKey": "private-key",
      "createdAt": 1_700_000_000,
    ]
    let prePolicyCredential = try decodeCredential(credentialFields)
    try assertNever(
      prePolicyCredential.transactionPreviewPolicy,
      "credential persisted before transaction-preview support"
    )

    var legacyCredentialFields = credentialFields
    legacyCredentialFields["showTransactionRequests"] = true
    legacyCredentialFields["previewApiBaseUrl"] = "https://preview.akita.example"
    legacyCredentialFields["previewToken"] = "preview-token"
    let migratedCredential = try decodeCredential(legacyCredentialFields)
    try assertRequired(
      migratedCredential.transactionPreviewPolicy,
      endpoint: "https://preview.akita.example",
      token: "preview-token",
      name: "legacy stored credential"
    )
    let reencodedCredential = try JSONSerialization.jsonObject(
      with: JSONEncoder().encode(migratedCredential)
    ) as? [String: Any]
    guard let reencodedCredential,
          reencodedCredential[TransactionPreviewPolicy.metadataKey] != nil,
          reencodedCredential["showTransactionRequests"] == nil,
          reencodedCredential["previewApiBaseUrl"] == nil,
          reencodedCredential["previewToken"] == nil
    else {
      throw HarnessError("stored credential did not re-encode with only the canonical policy")
    }

    try expectFailure("stored credential with partial legacy required tuple") {
      var partialCredentialFields = credentialFields
      partialCredentialFields["showTransactionRequests"] = true
      partialCredentialFields["previewApiBaseUrl"] = "https://preview.akita.example"
      _ = try decodeCredential(partialCredentialFields)
    }
    var partialCredentialFields = credentialFields
    partialCredentialFields["credentialId"] = "partial-credential-id"
    partialCredentialFields["showTransactionRequests"] = true
    partialCredentialFields["previewApiBaseUrl"] = "https://preview.akita.example"
    var invalidCredentialIds: [String?] = []
    let decodedCredentials = StoredPasskeyCredential.decodePersistedArray(
      try JSONSerialization.data(withJSONObject: [credentialFields, partialCredentialFields])
    ) { invalidCredentialIds.append($0) }
    guard decodedCredentials.map(\.credentialId) == ["credential-id"],
          invalidCredentialIds.count == 1,
          invalidCredentialIds[0] == "partial-credential-id"
    else {
      throw HarnessError("one invalid legacy tuple suppressed unrelated stored credentials")
    }

    var aliasedNeverCredential = credentialFields
    aliasedNeverCredential["credentialId"] = "-_8"
    var aliasedPartialCredential = credentialFields
    aliasedPartialCredential["credentialId"] = "+/8="
    aliasedPartialCredential["showTransactionRequests"] = true
    aliasedPartialCredential["previewApiBaseUrl"] = "https://preview.akita.example"
    let aliasedFallback = StoredPasskeyCredential.decodePersistedArray(
      try JSONSerialization.data(
        withJSONObject: [aliasedNeverCredential, aliasedPartialCredential]
      )
    )
    guard aliasedFallback.isEmpty else {
      throw HarnessError("invalid required alias fell back to a duplicate .never credential")
    }

    var aliasedRequiredCredential = credentialFields
    aliasedRequiredCredential["credentialId"] = "+/8="
    aliasedRequiredCredential["showTransactionRequests"] = true
    aliasedRequiredCredential["previewApiBaseUrl"] = "https://preview.akita.example"
    aliasedRequiredCredential["previewToken"] = "preview-token"
    let conflictingAliases = StoredPasskeyCredential.decodePersistedArray(
      try JSONSerialization.data(
        withJSONObject: [aliasedNeverCredential, aliasedRequiredCredential]
      )
    )
    guard conflictingAliases.isEmpty else {
      throw HarnessError("conflicting valid policy aliases were resolved by enumeration order")
    }

    var agreeingNeverAlias = credentialFields
    agreeingNeverAlias["credentialId"] = "+/8="
    let agreeingAliases = StoredPasskeyCredential.decodePersistedArray(
      try JSONSerialization.data(
        withJSONObject: [aliasedNeverCredential, agreeingNeverAlias]
      )
    )
    guard agreeingAliases.count == 1,
          passkeyCredentialCanonicalId(agreeingAliases[0].credentialId) == "-_8"
    else {
      throw HarnessError("agreeing credential-ID aliases did not deduplicate")
    }

    var legacyRequiredFields = credentialFields
    legacyRequiredFields["credentialId"] = "-_8"
    legacyRequiredFields["userName"] = "Legacy"
    legacyRequiredFields["showTransactionRequests"] = true
    legacyRequiredFields["previewApiBaseUrl"] = "https://preview.akita.example"
    legacyRequiredFields["previewToken"] = "preview-token"
    let legacyRequiredCredential = try decodeCredential(legacyRequiredFields)

    var keystoreNeverFields = credentialFields
    keystoreNeverFields["credentialId"] = "+/8="
    keystoreNeverFields["userName"] = "Keystore"
    let keystoreNeverCredential = try decodeCredential(keystoreNeverFields)
    let requiredVersusNever = StoredPasskeyCredential
      .resolveCombinedTransactionPreviewAuthority(
        legacyCredentials: [legacyRequiredCredential],
        keystoreCredentials: [keystoreNeverCredential]
      )
    guard requiredVersusNever.credentials.isEmpty else {
      throw HarnessError("keystore payload precedence bypassed cross-source policy disagreement")
    }

    var keystoreDifferentRequiredFields = keystoreNeverFields
    keystoreDifferentRequiredFields["showTransactionRequests"] = true
    keystoreDifferentRequiredFields["previewApiBaseUrl"] = "https://other-preview.akita.example"
    keystoreDifferentRequiredFields["previewToken"] = "different-token"
    let differingRequiredPolicies = StoredPasskeyCredential
      .resolveCombinedTransactionPreviewAuthority(
        legacyCredentials: [legacyRequiredCredential],
        keystoreCredentials: [try decodeCredential(keystoreDifferentRequiredFields)]
      )
    guard differingRequiredPolicies.credentials.isEmpty else {
      throw HarnessError("differing cross-source required policies were not quarantined")
    }

    var keystoreAgreeingRequiredFields = keystoreNeverFields
    keystoreAgreeingRequiredFields["showTransactionRequests"] = true
    keystoreAgreeingRequiredFields["previewApiBaseUrl"] = "https://preview.akita.example"
    keystoreAgreeingRequiredFields["previewToken"] = "preview-token"
    let agreeingCrossSourcePolicies = StoredPasskeyCredential
      .resolveCombinedTransactionPreviewAuthority(
        legacyCredentials: [legacyRequiredCredential],
        keystoreCredentials: [try decodeCredential(keystoreAgreeingRequiredFields)]
      )
    guard agreeingCrossSourcePolicies.credentials.count == 1,
          agreeingCrossSourcePolicies.credentials[0].userName == "Keystore"
    else {
      throw HarnessError("payload precedence did not follow cross-source policy agreement")
    }

    try assertControllerSecurityInvariants(sourcePath: CommandLine.arguments[1])

    print("Validated closed transaction-preview policy, persistence, and assertion flow guards.")
  }

  private static func decodeCredential(
    _ fields: [String: Any]
  ) throws -> StoredPasskeyCredential {
    try JSONDecoder().decode(
      StoredPasskeyCredential.self,
      from: JSONSerialization.data(withJSONObject: fields)
    )
  }

  private static func assertNever(
    _ policy: TransactionPreviewPolicy,
    _ name: String
  ) throws {
    guard case .never = policy else {
      throw HarnessError("\(name): expected .never")
    }
  }

  private static func assertRequired(
    _ policy: TransactionPreviewPolicy,
    endpoint: String,
    token: String,
    name: String
  ) throws {
    guard case .required(let actualEndpoint, let actualToken) = policy,
          actualEndpoint.absoluteString == endpoint,
          actualToken == token
    else {
      throw HarnessError("\(name): required policy payload did not match")
    }
  }

  private static func expectFailure(
    _ name: String,
    operation: () throws -> Void
  ) throws {
    do {
      try operation()
      throw HarnessError("\(name): expected failure")
    } catch is HarnessError {
      throw HarnessError("\(name): expected policy error, received harness error")
    } catch {
      return
    }
  }

  private static func assertControllerSecurityInvariants(sourcePath: String) throws {
    let source = try String(contentsOfFile: sourcePath, encoding: .utf8)
    for requiredFragment in [
      "private struct AssertionRequestSnapshot",
      "private var pendingOperation",
      "RejectingRedirectSessionDelegate()",
      "completionHandler(nil)",
      "phase: .loadingPreview",
      "phase: .authenticating",
      "store?.signingCredential(id: request.credential.credentialIdData)",
      "signingCredential.transactionPreviewPolicy == request.credential.transactionPreviewPolicy",
      "signingCredential.sign(authenticatorData + request.clientDataHash)",
    ] where !source.contains(requiredFragment) {
      throw HarnessError("controller is missing security invariant: \(requiredFragment)")
    }
    for forbiddenFragment in [
      "URLSession.shared",
      "pendingAssertionCredential",
      "pendingAssertionClientDataHash",
      "pendingAssertionRelyingPartyIdentifier",
      "assertionPhase",
      "pendingAssertionPrfInput",
      "isCompletingAssertion",
      "request.credential.sign(",
    ] where source.contains(forbiddenFragment) {
      throw HarnessError("controller retained mutable or redirecting path: \(forbiddenFragment)")
    }
  }
}

struct HarnessError: Error, CustomStringConvertible {
  let description: String

  init(_ description: String) {
    self.description = description
  }
}
