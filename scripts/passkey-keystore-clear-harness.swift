import Foundation

/// Host-side checks for `KeystoreClearPolicy`: clearing the provider removes only
/// this module's passkey records from the shared keystore, never the wallet's.
@main
struct PasskeyKeystoreClearHarness {
  struct HarnessError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
  }

  static func main() throws {
    let store: [String: String] = [
      // New layout: plaintext metadata + sealed material.
      "k/passkey-new": #"{"type":"hd-derived-p256","id":"passkey-new"}"#,
      "m/passkey-new": "sealed-material",
      "k/passkey-xhd": #"{"type":"xhd-derived-p256"}"#,
      "m/passkey-xhd": "sealed-material",
      // The wallet's own records in the same instance.
      "k/wallet-root": #"{"type":"hd-root-key"}"#,
      "m/wallet-root": "sealed-seed",
      "k/account-0": #"{"type":"ed25519"}"#,
      // Legacy single-record credentials (sealed whole).
      "legacy-passkey": "sealed:hd-derived-p256",
      "legacy-wallet-key": "sealed:hd-root-key",
      "legacy-undecodable": "sealed:???",
      // Malformed metadata is left alone.
      "k/broken": "not json",
    ]

    let removable = Set(KeystoreClearPolicy.keysToRemove(
      allKeys: Array(store.keys),
      payloadFor: { store[$0] },
      legacyTypeFor: { payload in
        guard payload.hasPrefix("sealed:") else { return nil }
        let type = String(payload.dropFirst("sealed:".count))
        return type == "???" ? nil : type
      }
    ))

    let expected: Set<String> = [
      "k/passkey-new", "m/passkey-new",
      "k/passkey-xhd", "m/passkey-xhd",
      "legacy-passkey",
    ]
    guard removable == expected else {
      throw HarnessError("expected \(expected.sorted()), got \(removable.sorted())")
    }

    // Without a master key nothing legacy can be recognised, so nothing legacy goes.
    let withoutMasterKey = Set(KeystoreClearPolicy.keysToRemove(
      allKeys: Array(store.keys),
      payloadFor: { store[$0] },
      legacyTypeFor: { _ in nil }
    ))
    guard withoutMasterKey == expected.subtracting(["legacy-passkey"]) else {
      throw HarnessError("without a master key, got \(withoutMasterKey.sorted())")
    }

    // clear() must sweep the keystore while the master key still exists.
    if CommandLine.arguments.count == 2 {
      let source = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8)
      guard let clearStart = source.range(of: "func clear() {"),
            let sweep = source.range(of: "removeOwnedKeystoreRecords()", range: clearStart.upperBound..<source.endIndex),
            let masterKeyDelete = source.range(of: "masterKeyQuery()", range: clearStart.upperBound..<source.endIndex),
            sweep.lowerBound < masterKeyDelete.lowerBound
      else {
        throw HarnessError("clear() must call removeOwnedKeystoreRecords() before deleting the master key")
      }
    }

    print("Validated that clearing removes only passkey records from the shared keystore.")
  }
}
