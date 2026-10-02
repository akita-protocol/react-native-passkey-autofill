export type ReactNativePasskeyAutofillModuleEvents = {
  onPasskeyAdded: (event: { success: boolean }) => void;
  onPasskeyAuthenticated: (event: { success: boolean }) => void;
};

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
  parentKeyId?: string;
  showTransactionRequests?: boolean;
  previewApiBaseUrl?: string;
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
  showTransactionRequests?: boolean;
  previewApiBaseUrl?: string;
  previewToken?: string;
};

export type RestoreCredentialsResult = {
  restored: string[];
  skipped: { credentialId: string; reason: "invalid" | "exists" | "mismatch" | "error" }[];
};
