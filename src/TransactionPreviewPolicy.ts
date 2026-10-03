import ReactNativePasskeyAutofill from "./ReactNativePasskeyAutofillModule";
import type { PasskeyAutofillTransactionPreviewPolicy } from "./ReactNativePasskeyAutofill.types";

/** The native bridge's `(required, apiBaseUrl, token)` triple for a policy. */
export type NativeTransactionPreviewConfiguration = readonly [
  required: boolean,
  apiBaseUrl: string,
  token: string,
];

const INVALID_ENDPOINT = "Native transaction preview requires a valid HTTPS endpoint.";

/**
 * Akita: maps the closed transaction-preview policy onto the native bridge's
 * `(required, apiBaseUrl, token)` triple, refusing anything else at runtime:
 *
 * - `{ kind: "never" }` → `[false, "", ""]`; any attached endpoint/token is an error.
 * - `{ kind: "required", httpsEndpoint, token }` → `[true, httpsEndpoint, token]`,
 *   where `httpsEndpoint` must be exactly an HTTPS origin (no credentials, path,
 *   query or fragment) and `token` a non-empty string without surrounding
 *   whitespace.
 *
 * The native side applies the same rules again and fails closed.
 */
export function mapTransactionPreviewPolicyToNative(
  policy: PasskeyAutofillTransactionPreviewPolicy,
): NativeTransactionPreviewConfiguration {
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
    throw new Error("Native transaction preview policy is invalid.");
  }

  const candidate = policy as Record<string, unknown>;
  if (candidate.kind === "never") {
    if ("httpsEndpoint" in candidate || "token" in candidate) {
      throw new Error("Disabled native transaction preview cannot include configuration.");
    }
    return [false, "", ""];
  }

  if (candidate.kind !== "required") {
    throw new Error("Native transaction preview policy is invalid.");
  }
  const httpsEndpoint = candidate.httpsEndpoint;
  const token = candidate.token;
  if (typeof httpsEndpoint !== "string" || typeof token !== "string") {
    throw new Error("Required native transaction preview configuration is incomplete.");
  }
  if (httpsEndpoint.trim() !== httpsEndpoint) {
    throw new Error(INVALID_ENDPOINT);
  }
  const hasHTTPSOriginPrefix = /^https:\/\//i.test(httpsEndpoint);
  const rawAuthority = hasHTTPSOriginPrefix ? httpsEndpoint.slice("https://".length) : "";
  const hasInvalidAuthorityCharacter = Array.from(rawAuthority).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return (
      codePoint <= 0x20 ||
      codePoint === 0x7f ||
      character === "\\" ||
      character === "/" ||
      character === "?" ||
      character === "#" ||
      character === "@"
    );
  });
  if (!hasHTTPSOriginPrefix || !rawAuthority || hasInvalidAuthorityCharacter) {
    throw new Error(INVALID_ENDPOINT);
  }

  let endpoint: URL;
  try {
    endpoint = new URL(httpsEndpoint);
  } catch {
    throw new Error(INVALID_ENDPOINT);
  }
  if (
    endpoint.protocol.toLowerCase() !== "https:" ||
    !endpoint.hostname ||
    endpoint.username ||
    endpoint.password ||
    endpoint.pathname !== "/" ||
    endpoint.search !== "" ||
    endpoint.hash !== ""
  ) {
    throw new Error(INVALID_ENDPOINT);
  }
  if (!token || token.trim() !== token) {
    throw new Error("Native transaction preview requires a non-empty token.");
  }
  return [true, httpsEndpoint, token];
}

/**
 * Akita: sets the closed transaction-preview policy of one stored passkey.
 * Validates the policy (see {@link mapTransactionPreviewPolicyToNative}) before
 * anything reaches native code; the native store then rewrites every record of
 * the credential so its aliases can never disagree.
 */
export async function configureCredentialTransactionPreviewPolicy(
  credentialId: string,
  policy: PasskeyAutofillTransactionPreviewPolicy,
): Promise<void> {
  const [required, apiBaseUrl, token] = mapTransactionPreviewPolicyToNative(policy);
  await ReactNativePasskeyAutofill.configureCredentialTransactionPreview(
    credentialId,
    required,
    apiBaseUrl,
    token,
  );
}
