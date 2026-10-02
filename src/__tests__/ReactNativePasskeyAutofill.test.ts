const mockModule = {
  setMasterKey: jest.fn(),
  setHdRootKeyId: jest.fn(),
  getHdRootKeyId: jest.fn(),
  configureIntentActions: jest.fn(),
  clearCredentials: jest.fn(),
  configureCredentialTransactionPreview: jest.fn(),
  restoreDerivedCredentials: jest.fn(),
  replaceCredentialIdentities: jest.fn(),
  refreshCredentialIdentities: jest.fn(),
  isProviderActive: jest.fn(),
  openProviderSettings: jest.fn(),
};

jest.mock("expo", () => ({
  requireNativeModule: () => mockModule,
  NativeModule: class {},
}));

import { requireNativeModule } from "expo";
import ReactNativePasskeyAutofill from "../index";

describe("ReactNativePasskeyAutofill", () => {
  it("should be defined", () => {
    expect(ReactNativePasskeyAutofill).toBeDefined();
  });

  it("should call setMasterKey", async () => {
    const mockModule = requireNativeModule("ReactNativePasskeyAutofill");
    await ReactNativePasskeyAutofill.setMasterKey("secret");
    expect(mockModule.setMasterKey).toHaveBeenCalledWith("secret");
  });

  it("should configure credential-scoped native transaction preview", async () => {
    const mockModule = requireNativeModule("ReactNativePasskeyAutofill");
    await ReactNativePasskeyAutofill.configureCredentialTransactionPreview(
      "credential",
      true,
      "https://gateway.akita.community",
      "token",
    );
    expect(mockModule.configureCredentialTransactionPreview).toHaveBeenCalledWith(
      "credential",
      true,
      "https://gateway.akita.community",
      "token",
    );
  });

  it("should pass synced passkeys to the native restore", async () => {
    const mockModule = requireNativeModule("ReactNativePasskeyAutofill");
    mockModule.restoreDerivedCredentials.mockResolvedValue({ restored: ["abc"], skipped: [] });
    const credential = {
      credentialId: "abc",
      rpId: "example.com",
      userIdBase64Url: "dXNlcg",
      userName: "alice",
      derivationHandle: "user",
    };
    await expect(ReactNativePasskeyAutofill.restoreDerivedCredentials([credential])).resolves.toEqual({
      restored: ["abc"],
      skipped: [],
    });
    expect(mockModule.restoreDerivedCredentials).toHaveBeenCalledWith([credential]);
  });
});
