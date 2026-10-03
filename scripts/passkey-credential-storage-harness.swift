import Foundation

/// Host-side checks for how the iOS provider stores passkeys: the legacy
/// plaintext App Group store is only ever migrated out of (into sealed keystore
/// records), never written with key material or preview tokens.
@main
struct PasskeyCredentialStorageHarness {
  static func main() throws {
    guard CommandLine.arguments.count == 3 else {
      throw HarnessError("usage: harness <PasskeyCredentialStore.swift> <CredentialProviderViewController.swift>")
    }
    try testMigrationPlan()
    try assertStoreInvariants(sourcePath: CommandLine.arguments[1])
    try assertRegistrationInvariants(sourcePath: CommandLine.arguments[2])
    print("Validated legacy credential migration, sealed-only storage, and no-overwrite registration.")
  }

  private static let required = TransactionPreviewPolicy.required(
    httpsEndpoint: URL(string: "https://preview.akita.example")!,
    token: "preview-token"
  )

  private static func entry(
    _ id: String,
    privateKey: String = "c2VjcmV0",
    preview: Bool = false,
    extra: [String: Any] = [:]
  ) -> [String: Any] {
    var fields: [String: Any] = [
      "credentialId": id,
      "relyingPartyIdentifier": "example.com",
      "userName": "Akita",
      "userHandle": "dXNlcg",
      "privateKey": privateKey,
      "publicKey": "cHVibGlj",
      "createdAt": 1_700_000_000,
    ]
    if preview {
      fields["showTransactionRequests"] = true
      fields["previewApiBaseUrl"] = "https://preview.akita.example"
      fields["previewToken"] = "preview-token"
    }
    return fields.merging(extra) { _, new in new }
  }

  private static func testMigrationPlan() throws {
    // No sealed record: sealed with its policy, plaintext copy dropped.
    var plan = LegacyCredentialMigration.plan(entries: [entry("-_8", preview: true)]) { _ in .absent }
    try require(plan.toSeal.count == 1 && plan.remainingEntries.isEmpty, "absent credential was not sealed")
    try require(plan.toSeal[0].transactionPreviewPolicy == required, "sealing dropped the preview policy")
    try require(plan.changesLegacyStore, "migration did not report a change")

    // Agreeing sealed record: plaintext copy dropped, nothing re-sealed.
    plan = LegacyCredentialMigration.plan(entries: [entry("-_8", preview: true)]) { _ in .present(required) }
    try require(plan.toSeal.isEmpty && plan.remainingEntries.isEmpty, "agreeing copy was not dropped")

    // Disagreeing or unusable sealed record: kept (quarantined) without its key.
    for state in [SealedCredentialState.present(.never), .unusable] {
      plan = LegacyCredentialMigration.plan(entries: [entry("-_8", preview: true)]) { _ in state }
      try require(plan.toSeal.isEmpty, "a conflicting credential was sealed over an existing record")
      try requireStripped(plan.remainingEntries, count: 1, "conflicting copy")
    }

    // Malformed policy: never sealed, kept without its key.
    plan = LegacyCredentialMigration.plan(
      entries: [entry("-_8", extra: ["showTransactionRequests": true])]
    ) { _ in .absent }
    try require(plan.toSeal.isEmpty, "a malformed policy was sealed")
    try requireStripped(plan.remainingEntries, count: 1, "malformed copy")

    // Two aliases in the legacy store: the first is sealed; an agreeing alias is
    // dropped, a disagreeing one stays quarantined without its key.
    plan = LegacyCredentialMigration.plan(entries: [entry("-_8"), entry("+/8=")]) { _ in .absent }
    try require(plan.toSeal.count == 1 && plan.remainingEntries.isEmpty, "agreeing aliases were not collapsed")
    plan = LegacyCredentialMigration.plan(entries: [entry("-_8"), entry("+/8=", preview: true)]) { _ in .absent }
    try require(plan.toSeal.count == 1, "first alias was not sealed")
    try requireStripped(plan.remainingEntries, count: 1, "disagreeing alias")

    // Key-less entries stay; foreign values are untouched; no-op reports no change.
    plan = LegacyCredentialMigration.plan(entries: [entry("-_8", privateKey: ""), "foreign"]) { _ in .absent }
    try require(plan.toSeal.isEmpty && plan.remainingEntries.count == 2, "key-less entry handling changed")
    try require(!plan.changesLegacyStore, "a no-op migration rewrote the legacy store")
  }

  private static func requireStripped(_ entries: [Any], count: Int, _ name: String) throws {
    try require(entries.count == count, "\(name): expected \(count) remaining entries")
    for value in entries {
      guard let fields = value as? [String: Any] else { continue }
      try require((fields["privateKey"] as? String) == "", "\(name): plaintext private key survived")
    }
  }

  private static func assertStoreInvariants(sourcePath: String) throws {
    let source = try String(contentsOfFile: sourcePath, encoding: .utf8)
    for fragment in [
      "func migrateLegacyCredentials()",
      "throw PasskeyCredentialStoreError.credentialAlreadyExists",
      "throw PasskeyCredentialStoreError.masterKeyUnavailable",
      "try saveKeystoreCredential(credential)",
    ] {
      try require(source.contains(fragment), "store is missing: \(fragment)")
    }
    for fragment in [
      // The sealed path used to be extension-only; the app process wrote plaintext.
      "#if PASSKEY_AUTOFILL_EXTENSION",
      "JSONEncoder().encode(credentials)",
      "policy.write(to: &entry)",
    ] {
      try require(!source.contains(fragment), "store still has a plaintext write path: \(fragment)")
    }
  }

  /// Re-registering an existing (deterministically derived) credential must fail
  /// rather than overwrite it and its preview policy.
  private static func assertRegistrationInvariants(sourcePath: String) throws {
    let source = try String(contentsOfFile: sourcePath, encoding: .utf8)
    for fragment in [
      "store.hasCredentialRecord(id: credentialId)",
      "request.excludedCredentials",
      "return .matchedExcludedCredential",
      "catch PasskeyCredentialStoreError.credentialAlreadyExists",
    ] {
      try require(source.contains(fragment), "registration is missing: \(fragment)")
    }
  }

  private static func require(_ condition: Bool, _ message: String) throws {
    guard condition else { throw HarnessError(message) }
  }
}

struct HarnessError: Error, CustomStringConvertible {
  let description: String
  init(_ description: String) { self.description = description }
}
