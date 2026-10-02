// Usage: swift scripts/generate-site-credential-vectors.swift > test-vectors/site-credential-vectors.json
//
// Generates site passkey derivation vectors with the iOS provider's code.
// SiteCredentialDerivation below is copied verbatim from
// ios/AutofillCredentialProvider/PasskeyCredentialStore.swift; keep them identical.
import CryptoKit
import Foundation

enum PasskeyCredentialStoreError: Error { case invalidPrivateKey }

extension Data {
  var hex: String { map { String(format: "%02x", $0) }.joined() }
}

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

let root = Data((0..<32).map { UInt8($0) })
let cases: [(name: String, rpId: String, userName: String)] = [
  ("ascii-mixed-case-email", "example.com", "Alice@Example.ORG"),
  ("ascii-lowercase", "webauthn.io", "bob"),
  ("greek-final-sigma", "example.com", "ΟΔΥΣΣΕΥΣ"),
  ("greek-sigma-before-digit", "example.com", "ΑΣ1Β"),
  ("dotted-capital-i", "example.com", "İstanbul"),
  ("sharp-s", "accounts.example.org", "STRASSE ß"),
  ("titlecase-letter", "example.com", "ǅemal"),
  ("akita-connect", "akita.community", "Akita Hyperspace"),
  ("empty-name", "example.com", ""),
]

var vectors: [[String: Any]] = []
for c in cases {
  let handle = SiteCredentialDerivation.handle(forUserName: c.userName)
  let key = try SiteCredentialDerivation.privateKey(rootSecret: root, rpId: c.rpId, handle: handle)
  let spki = key.publicKey.derRepresentation
  vectors.append([
    "name": c.name,
    "rpId": c.rpId,
    "userNameUtf8Hex": Data(c.userName.utf8).hex,
    "handleUtf8Hex": Data(handle.utf8).hex,
    "privateKeyHex": key.rawRepresentation.hex,
    "publicKeySpkiHex": spki.hex,
    "credentialIdHex": SiteCredentialDerivation.credentialId(publicKey: key.publicKey).hex,
  ])
}
let json = try JSONSerialization.data(
  withJSONObject: ["rootHex": root.hex, "rule": "handle = per-code-point lowercase(user.name)", "source": "iOS SiteCredentialDerivation (CryptoKit)", "vectors": vectors],
  options: [.prettyPrinted, .sortedKeys])
print(String(data: json, encoding: .utf8)!)
