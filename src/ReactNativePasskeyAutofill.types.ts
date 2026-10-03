export type ReactNativePasskeyAutofillModuleEvents = {
  onPasskeyAdded: (event: { success: boolean }) => void;
  onPasskeyAuthenticated: (event: { success: boolean; credentialId?: string }) => void;
};

/**
 * Akita: whether a passkey's assertions must first show the user a native
 * transaction preview. Closed: exactly one of these two shapes, nothing partial.
 * `httpsEndpoint` is an HTTPS origin (no path, query or fragment); the provider
 * fetches `/akita/passkey-previews/<credentialId>` from it with `token` as a
 * bearer token.
 */
export type PasskeyAutofillTransactionPreviewPolicy =
  | { kind: "never" }
  | { kind: "required"; httpsEndpoint: string; token: string };

export type PasskeyAutofillCredentialIdentity = {
  credentialId: string;
  relyingPartyIdentifier?: string;
  rpId?: string;
  origin?: string;
  userName?: string;
  name?: string;
  userHandle: string;
  userId?: string;
  privateKey?: string;
  privateKeyBase64?: string;
  publicKey?: string;
  publicKeyBase64?: string;
  createdAt?: number;
  lastUsedAt?: number;
  parentKeyId?: string;
  /**
   * The version of the identity derivation logic used for this credential.
   * Pinned for the life of the credential.
   */
  derivationVersion?: number;
  /**
   * The scheme the passkey key was derived from. Absent means "bip32-ed25519".
   * Pinned for the life of the credential — changing it changes the secret
   * every relying party is bound to.
   */
  derivationScheme?: string;
  /** Akita: the credential's transaction-preview policy (getStoredCredentials, iOS and Android). */
  transactionPreviewPolicy?: PasskeyAutofillTransactionPreviewPolicy;
  /**
   * Akita, legacy flat view of {@link transactionPreviewPolicy}: whether
   * assertions must show a native transaction preview first.
   */
  showTransactionRequests?: boolean;
  /** Akita, legacy: the HTTPS origin the transaction preview is fetched from. */
  previewApiBaseUrl?: string;
  /** Akita, legacy: the preview bearer token. */
  previewToken?: string;
  /** Unpadded base64url of the site's WebAuthn user.id (same meaning on iOS and Android). */
  userIdBase64Url?: string;
  /** The site's user name as shown to the user (same meaning on iOS and Android). */
  userDisplayName?: string;
};

/** A synced site passkey for restoreDerivedCredentials. */
export type RestorableCredential = {
  /** Unpadded base64url credential ID: SHA-256 of the public key's SPKI. */
  credentialId: string;
  rpId: string;
  userIdBase64Url: string;
  userName: string;
  /** The exact handle string the key was derived from. */
  derivationHandle: string;
  /** Milliseconds since the epoch. */
  createdAt?: number;
  /**
   * The closed transaction-preview policy. Send either this or the legacy flat
   * fields below, never both; a partial or contradictory policy is skipped as
   * `invalid`. Absent both, the restored passkey requires no preview.
   */
  transactionPreviewPolicy?: PasskeyAutofillTransactionPreviewPolicy;
  /** @deprecated use {@link transactionPreviewPolicy} */
  showTransactionRequests?: boolean;
  /** @deprecated use {@link transactionPreviewPolicy} */
  previewApiBaseUrl?: string;
  /** @deprecated use {@link transactionPreviewPolicy} */
  previewToken?: string;
};

export type RestoreCredentialsResult = {
  restored: string[];
  skipped: { credentialId: string; reason: "invalid" | "exists" | "mismatch" | "error" }[];
};

/**
 * Capabilities advertised by this credential provider. Exposed so the
 * surrounding wallet UI / RP-side wallet can know which WebAuthn extensions
 * are wired up natively before issuing a passkey request.
 */
export type PasskeyAutofillCapabilities = {
  /**
   * Whether the WebAuthn `prf` extension (a.k.a. `hmac-secret`) is supported
   * by this credential provider. PRF outputs are derived deterministically
   * from the wallet's parent secret (the P-256 main key or legacy HD root)
   * so that restoring the wallet seed reproduces the same secrets on another
   * device.
   */
  prf: boolean;
};

export const PASSKEY_AUTOFILL_CAPABILITIES: PasskeyAutofillCapabilities = {
  prf: true,
};
