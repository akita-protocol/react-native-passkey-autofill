const mockModule: Record<string, jest.Mock> = {
  configureCredentialTransactionPreview: jest.fn(),
};

jest.mock("expo", () => ({
  requireNativeModule: () => mockModule,
  NativeModule: class {},
}));

jest.mock("react-native", () => ({ Platform: { OS: "ios" } }));

import {
  configureCredentialTransactionPreviewPolicy,
  mapTransactionPreviewPolicyToNative,
  type PasskeyAutofillTransactionPreviewPolicy,
} from "../index";

describe("closed transaction preview policy", () => {
  beforeEach(() => mockModule.configureCredentialTransactionPreview.mockReset());

  it("maps the closed policy vocabulary to the native ABI", () => {
    expect(mapTransactionPreviewPolicyToNative({ kind: "never" })).toEqual([false, "", ""]);
    expect(
      mapTransactionPreviewPolicyToNative({
        kind: "required",
        httpsEndpoint: "https://preview.akita.example",
        token: "preview-token",
      }),
    ).toEqual([true, "https://preview.akita.example", "preview-token"]);
  });

  it("rejects a non-HTTPS required endpoint", () => {
    expect(() =>
      mapTransactionPreviewPolicyToNative({
        kind: "required",
        httpsEndpoint: "http://preview.akita.example",
        token: "preview-token",
      }),
    ).toThrow("valid HTTPS endpoint");
  });

  it.each([
    "https://preview.akita.example/",
    "https://preview.akita.example/v1",
    "https://preview.akita.example?tenant=akita",
    "https://preview.akita.example#preview",
    "https://preview.akita.example\\v1",
    "https:preview.akita.example",
    String.raw`https:\preview.akita.example`,
    "https://@preview.akita.example",
    " https://preview.akita.example",
  ])("rejects a required endpoint that is not an exact origin: %s", (httpsEndpoint) => {
    expect(() =>
      mapTransactionPreviewPolicyToNative({
        kind: "required",
        httpsEndpoint,
        token: "preview-token",
      }),
    ).toThrow("valid HTTPS endpoint");
  });

  it.each(["", " preview-token", "preview-token\n"])("rejects the token %j", (token) => {
    expect(() =>
      mapTransactionPreviewPolicyToNative({
        kind: "required",
        httpsEndpoint: "https://preview.akita.example",
        token,
      }),
    ).toThrow("non-empty token");
  });

  it("rejects a partial required policy at the runtime boundary", () => {
    const partialPolicy = {
      kind: "required",
      httpsEndpoint: "https://preview.akita.example",
    } as unknown as PasskeyAutofillTransactionPreviewPolicy;

    expect(() => mapTransactionPreviewPolicyToNative(partialPolicy)).toThrow("incomplete");
  });

  it("rejects configuration attached to the never policy", () => {
    const openNeverPolicy = {
      kind: "never",
      token: "stale-token",
    } as unknown as PasskeyAutofillTransactionPreviewPolicy;

    expect(() => mapTransactionPreviewPolicyToNative(openNeverPolicy)).toThrow(
      "cannot include configuration",
    );
  });

  it("rejects an unknown policy kind", () => {
    const unknownPolicy = {
      kind: "sometimes",
    } as unknown as PasskeyAutofillTransactionPreviewPolicy;
    expect(() => mapTransactionPreviewPolicyToNative(unknownPolicy)).toThrow("invalid");
  });

  it("configures a credential through the native triple", async () => {
    await configureCredentialTransactionPreviewPolicy("credential", {
      kind: "required",
      httpsEndpoint: "https://gateway.akita.community",
      token: "token",
    });
    expect(mockModule.configureCredentialTransactionPreview).toHaveBeenCalledWith(
      "credential",
      true,
      "https://gateway.akita.community",
      "token",
    );

    await configureCredentialTransactionPreviewPolicy("credential", { kind: "never" });
    expect(mockModule.configureCredentialTransactionPreview).toHaveBeenLastCalledWith(
      "credential",
      false,
      "",
      "",
    );
  });

  it("never reaches native code with an invalid policy", async () => {
    await expect(
      configureCredentialTransactionPreviewPolicy("credential", {
        kind: "required",
        httpsEndpoint: "https://gateway.akita.community/path",
        token: "token",
      }),
    ).rejects.toThrow("valid HTTPS endpoint");
    expect(mockModule.configureCredentialTransactionPreview).not.toHaveBeenCalled();
  });
});
