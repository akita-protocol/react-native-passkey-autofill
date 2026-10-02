import { NativeModule, requireNativeModule } from "expo";
import { Platform } from "react-native";

import {
  PasskeyAutofillCredentialIdentity,
  ReactNativePasskeyAutofillModuleEvents,
  RestorableCredential,
  RestoreCredentialsResult,
} from "./ReactNativePasskeyAutofill.types";

declare class ReactNativePasskeyAutofillModule extends NativeModule<ReactNativePasskeyAutofillModuleEvents> {
  /**
   * Persists the keystore master key as **raw bytes**, so a non-zeroable hex
   * string is never materialized in the JS heap (immutable JS strings can't be
   * wiped and linger until GC). The caller should zero the `Uint8Array` after
   * the promise resolves.
   */
  setMasterKey(secret: Uint8Array): Promise<void>;
  /**
   * Sets the ID of the keystore record to use as the parent secret for passkey
   * derivation. The record must be a deterministic-P256 main key (64 bytes).
   */
  setMainKeyId(id: string): Promise<void>;
  /**
   * Returns the ID of the keystore record currently used as the parent secret
   * for passkey derivation.
   */
  getMainKeyId(): Promise<string | null>;
  /**
   * Akita: shares the wallet's HD root secret with the provider as **raw bytes**.
   * When set, every new site passkey derives from it (derivation scheme
   * `akita-hd-root`) instead of a key store record. Stored in the Keychain
   * (iOS) / under an AndroidKeyStore key (Android), never in plaintext; the
   * promise rejects if it could not be stored. Zero the array after it resolves.
   */
  setHdRootSecret(secret: Uint8Array): Promise<void>;
  /** @deprecated use {@link setMainKeyId} */
  setHdRootKeyId(id: string): Promise<void>;
  /** @deprecated use {@link getMainKeyId} */
  getHdRootKeyId(): Promise<string | null>;
  configureIntentActions(getPasskeyAction: string, createPasskeyAction: string): Promise<void>;
  /**
   * Removes every passkey this module owns. The native store is shared with the
   * wallet's keystore, so only records that read back as this module's passkey
   * types are removed; the wallet's seeds, roots and account keys are untouched.
   */
  clearCredentials(): Promise<void>;
  /**
   * Removes the passkey stored under `credentialId`. Like {@link clearCredentials}
   * this only ever removes a record that reads back as one of this module's
   * passkey types: an id that addresses a wallet-owned keystore record removes
   * nothing.
   */
  deleteCredential(credentialId: string): Promise<void>;
  /**
   * Akita: requires (or stops requiring) a native transaction preview before
   * `credentialId` signs an assertion. When enabled, the provider fetches the
   * pending preview from `apiBaseUrl` with `token` as a bearer token, checks it
   * matches the request's client data, and asks the user to approve it.
   */
  configureCredentialTransactionPreview(
    credentialId: string,
    enabled: boolean,
    apiBaseUrl: string,
    token: string,
  ): Promise<void>;
  /**
   * iOS: returns the identities currently published to the AutoFill
   * `ASCredentialIdentityStore`. Android: no-op returning `[]` because the
   * native Credential Provider service reads credentials directly from MMKV
   * and there is no separate identity store to query.
   */
  getStoredCredentials(): Promise<PasskeyAutofillCredentialIdentity[]>;
  /**
   * Akita: adds synced site passkeys to this device. Each key is re-derived from
   * the wallet's HD root (see {@link setHdRootSecret}) and must reproduce its
   * credential ID. Credentials that already exist on the device are skipped, not
   * overwritten.
   */
  restoreDerivedCredentials(credentials: RestorableCredential[]): Promise<RestoreCredentialsResult>;
  /**
   * iOS: returns diagnostic strings from the AutoFill extension.
   * Android: no-op returning `[]`.
   */
  getDiagnostics(): Promise<string[]>;
  /**
   * Replaces the iOS AutoFill passkey identity store with credentials
   * available to the native Credential Provider extension. Each item must
   * include a credential id, relying party (`relyingPartyIdentifier`,
   * `rpId`, or `origin`), user handle, and P-256 private key material.
   * Android ignores this method (no-op) because the provider reads MMKV
   * directly.
   */
  replaceCredentialIdentities(credentials: PasskeyAutofillCredentialIdentity[]): Promise<void>;
  refreshCredentialIdentities(): Promise<void>;
  /**
   * Resolves to `true` when this app is registered as the active
   * credential/autofill provider on the current device (Android 14+
   * credential provider or iOS AutoFill). Useful for gating passkey UI
   * and for E2E tests that need to confirm the prompt that appears
   * belongs to this provider and not a third party.
   */
  isProviderActive(): Promise<boolean>;
  /**
   * Opens the OS credential/autofill provider settings screen so the
   * user can enable this app as the active provider. Resolves to `true`
   * if a settings screen could be launched, `false` otherwise.
   */
  openProviderSettings(): Promise<boolean>;
}

// This call loads the native module object from the JSI.
const nativeModule = requireNativeModule<ReactNativePasskeyAutofillModule>(
  "ReactNativePasskeyAutofill",
);

// A handful of methods are only implemented in the iOS native module because
// they interact with `ASCredentialIdentityStore`, which has no Android
// equivalent (the Android Credential Provider service reads credentials
// directly from MMKV on each request).
if (Platform.OS === "android") {
  const noops: Record<string, (...args: unknown[]) => Promise<unknown>> = {
    replaceCredentialIdentities: () => Promise.resolve(),
    refreshCredentialIdentities: () => Promise.resolve(),
    getStoredCredentials: () => Promise.resolve([]),
    getDiagnostics: () => Promise.resolve([]),
  };
  for (const name of Object.keys(noops)) {
    if (typeof (nativeModule as unknown as Record<string, unknown>)[name] !== "function") {
      (nativeModule as unknown as Record<string, unknown>)[name] = noops[name];
    }
  }
}

export default nativeModule;
