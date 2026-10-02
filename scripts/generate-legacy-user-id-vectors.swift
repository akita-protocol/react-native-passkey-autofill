// Usage: swift scripts/generate-legacy-user-id-vectors.swift > test-vectors/site-credential-vectors-legacy-user-id.json
// The rule iOS used before site passkeys moved to user.name (kept so sync can
// recognize passkeys created with it).
// Generates site-passkey derivation vectors using the exact iOS provider logic
// (CredentialProviderViewController.domainSpecificKeyPair, userHandleString,
// WebAuthn.credentialId), so other platforms can be checked against iOS.
import CryptoKit
import Foundation

extension Data {
  func base64URLEncodedString() -> String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
  var hex: String { map { String(format: "%02x", $0) }.joined() }
  init(hex: String) {
    var data = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      data.append(UInt8(hex[index..<next], radix: 16)!)
      index = next
    }
    self = data
  }
}

// Copy of ASPasskeyCredentialIdentity.userHandleString
func userHandleString(_ userHandle: Data) -> String {
  String(data: userHandle, encoding: .utf8) ?? userHandle.base64URLEncodedString()
}

// Copy of CredentialProviderViewController.domainSpecificKeyPair, also reporting the counter used.
func domainSpecificKeyPair(derivedParentSecret: Data, origin: String, userHandle: String, counter: UInt32 = 0) -> (P256.Signing.PrivateKey, UInt32)? {
  var input = Data()
  input.append(derivedParentSecret)
  input.append(contentsOf: origin.utf8)
  input.append(contentsOf: userHandle.utf8)
  for attempt in counter..<(counter + 16) {
    var candidateInput = input
    var bigEndianAttempt = attempt.bigEndian
    withUnsafeBytes(of: &bigEndianAttempt) { candidateInput.append(contentsOf: $0) }
    let digest = SHA512.hash(data: candidateInput)
    if let key = try? P256.Signing.PrivateKey(rawRepresentation: Data(digest.prefix(32))) {
      return (key, attempt)
    }
  }
  return nil
}

let root = Data((0..<32).map { UInt8($0) })
let cases: [(String, String, Data)] = [
  ("ascii-mixed-case", "example.com", Data("AbC-User_42".utf8)),
  ("random-bytes-not-utf8", "webauthn.io", Data(hex: "ff00a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e")),
  ("akita-connect-random-32", "akita.community", Data(hex: "c3a9e1f28d0b4c5a6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5")),
  ("utf8-with-bom", "example.com", Data([0xEF, 0xBB, 0xBF]) + Data("abc".utf8)),
  ("non-ascii-case", "example.com", Data("ÄÖ-ΣΣ-İ-ß".utf8)),
  ("nul-bytes", "example.com", Data(repeating: 0, count: 16)),
  ("uppercase-email", "accounts.example.org", Data("Alice@Example.ORG".utf8)),
]

var out: [[String: Any]] = []
for (name, rpId, userId) in cases {
  let canonical = userHandleString(userId).lowercased()
  guard let (key, counter) = domainSpecificKeyPair(derivedParentSecret: root, origin: rpId, userHandle: canonical) else {
    fatalError("no valid key for \(name)")
  }
  let spki = key.publicKey.derRepresentation
  out.append([
    "name": name,
    "rpId": rpId,
    "userIdHex": userId.hex,
    "canonicalUserHandleUtf8Hex": Data(canonical.utf8).hex,
    "counter": counter,
    "privateKeyHex": key.rawRepresentation.hex,
    "publicKeySpkiHex": spki.hex,
    "credentialIdHex": Data(SHA256.hash(data: spki)).hex,
  ])
}
let json = try JSONSerialization.data(withJSONObject: ["rootHex": root.hex, "source": "iOS provider logic (CryptoKit)", "vectors": out], options: [.prettyPrinted, .sortedKeys])
print(String(data: json, encoding: .utf8)!)
