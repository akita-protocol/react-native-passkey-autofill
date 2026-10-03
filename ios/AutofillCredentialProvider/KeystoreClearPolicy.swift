import Foundation

/// Decides which keys of the SHARED keystore MMKV instance `clear()` may remove.
///
/// The instance is also the wallet's key store: it holds the seed, the HD roots
/// and every account key, so clearing it wholesale would destroy the wallet.
/// Only this module's own passkey records go: `k/<id>` metadata records whose
/// type is a passkey (with their `m/<id>` material), and legacy single-record
/// credentials whose decoded type is a passkey. Legacy records that can't be
/// decoded (no master key) are left alone, like everything else unrecognised.
///
/// Kept in step with `KeystoreRecords.keysToRemoveForClear` on Android.
enum KeystoreClearPolicy {
  static let metadataPrefix = "k/"
  static let materialPrefix = "m/"

  static func isPasskeyRecordType(_ type: String) -> Bool {
    type == "hd-derived-p256" || type == "xhd-derived-p256"
  }

  /// - Parameters:
  ///   - payloadFor: the stored string for a key, or nil if missing.
  ///   - legacyTypeFor: the `type` of a decoded legacy record, or nil if it can't be decoded.
  static func keysToRemove(
    allKeys: [String],
    payloadFor: (String) -> String?,
    legacyTypeFor: (String) -> String?
  ) -> [String] {
    var removable: [String] = []
    for key in allKeys {
      // Removed alongside its `k/` metadata below, if this module owns it.
      if key.hasPrefix(materialPrefix) { continue }
      guard let payload = payloadFor(key) else { continue }

      let type: String?
      if key.hasPrefix(metadataPrefix) {
        let object = payload.data(using: .utf8).flatMap { try? JSONSerialization.jsonObject(with: $0) }
        type = (object as? [String: Any])?["type"] as? String
      } else {
        type = legacyTypeFor(payload)
      }
      guard let type, isPasskeyRecordType(type) else { continue }

      removable.append(key)
      if key.hasPrefix(metadataPrefix) {
        removable.append(materialPrefix + key.dropFirst(metadataPrefix.count))
      }
    }
    return removable
  }
}
