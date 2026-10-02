import AuthenticationServices
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import UIKit

final class CredentialProviderViewController: ASCredentialProviderViewController {
  private let store = PasskeyCredentialStore()
  private var pendingRegistrationRequest: ASPasskeyCredentialRequest?
  private var pendingRegistrationIdentity: ASPasskeyCredentialIdentity?
  private var pendingAssertionCredential: StoredPasskeyCredential?
  private var pendingAssertionClientDataHash: Data?
  private var pendingAssertionRelyingPartyIdentifier: String?
  private var isCompletingRegistration = false
  private var isCompletingAssertion = false
  private var isLoadingTransactionPreview = false
  private var hasPresentedInterface = false
  private var authContext: LAContext?
  private let activityIndicator = UIActivityIndicatorView(style: .large)
  private let statusLabel = UILabel()

  override func viewDidLoad() {
    super.viewDidLoad()
    configureView()
  }

  override func viewDidAppear(_ animated: Bool) {
    super.viewDidAppear(animated)
    hasPresentedInterface = true

    DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
      guard let self else {
        return
      }
      if self.pendingRegistrationRequest != nil {
        self.authenticateAndCompleteRegistration()
      } else if self.pendingAssertionCredential != nil {
        self.prepareTransactionPreviewOrAuthenticate()
      }
    }
  }

  override func prepareCredentialList(
    for serviceIdentifiers: [ASCredentialServiceIdentifier],
    requestParameters: ASPasskeyCredentialRequestParameters
  ) {
    guard #available(iOSApplicationExtension 17.0, *) else {
      cancel(code: .failed, message: "Passkeys require iOS 17 or newer.")
      return
    }

    let relyingPartyIdentifier = requestParameters.relyingPartyIdentifier
    let allowedCredentials = Set(requestParameters.allowedCredentials.map { $0.base64URLEncodedString() })
    guard let credential = store?.credentials(
            relyingPartyIdentifier: relyingPartyIdentifier
          ).first(where: { allowedCredentials.isEmpty || allowedCredentials.contains($0.credentialIdData.base64URLEncodedString()) })
    else {
      cancel(code: .credentialIdentityNotFound, message: "No passkey is available.")
      return
    }

    prepareAssertion(
      credential: credential,
      clientDataHash: requestParameters.clientDataHash,
      relyingPartyIdentifier: relyingPartyIdentifier
    )
  }

  override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
    guard #available(iOSApplicationExtension 17.0, *),
          let request = credentialRequest as? ASPasskeyCredentialRequest
    else {
      cancel(code: .failed, message: "Unsupported credential request.")
      return
    }

    guard request.credentialIdentity is ASPasskeyCredentialIdentity else {
      cancel(code: .credentialIdentityNotFound, message: "Credential identity not found.")
      return
    }

    cancel(code: .userInteractionRequired, message: "User verification is required.")
  }

  override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
    guard #available(iOSApplicationExtension 17.0, *),
          let request = credentialRequest as? ASPasskeyCredentialRequest
    else {
      cancel(code: .failed, message: "Unsupported credential request.")
      return
    }

    guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity,
          let credential = store?.credential(id: identity.credentialID)
    else {
      cancel(code: .credentialIdentityNotFound, message: "Credential identity not found.")
      return
    }

    prepareAssertion(
      credential: credential,
      clientDataHash: request.clientDataHash,
      relyingPartyIdentifier: identity.relyingPartyIdentifier
    )
  }

  override func prepareInterface(forPasskeyRegistration request: ASCredentialRequest) {
    store?.appendDiagnostic("prepareInterface(forPasskeyRegistration)")
    guard #available(iOSApplicationExtension 17.0, *),
          let request = request as? ASPasskeyCredentialRequest,
          let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
    else {
      cancel(code: .failed, message: "Unsupported passkey registration request.")
      return
    }

    pendingRegistrationRequest = request
    pendingRegistrationIdentity = identity
    showCheckingPasskeys()

    if hasPresentedInterface {
      DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
        self?.authenticateAndCompleteRegistration()
      }
    }
  }

  override func prepareInterfaceForExtensionConfiguration() {
    extensionContext.completeExtensionConfigurationRequest()
  }

  private func completePendingRegistration() {
    store?.appendDiagnostic("completePendingRegistration")
    showCheckingPasskeys()

    guard #available(iOSApplicationExtension 17.0, *),
          let request = pendingRegistrationRequest,
          let identity = pendingRegistrationIdentity
    else {
      cancel(code: .failed, message: "Unsupported passkey registration request.")
      return
    }

    do {
      guard let store else {
        self.store?.appendDiagnostic("missing wallet root-key state")
        showFailure("Wallet root key is not available. Open Akita once, unlock it, then try again.")
        return
      }

      let parentKeyId = store.hdRootKeyId()
      let derivedParentSecret = try store.hdRootKeySecret()
      let privateKey = try SiteCredentialDerivation.privateKey(
        rootSecret: derivedParentSecret,
        rpId: identity.relyingPartyIdentifier,
        handle: SiteCredentialDerivation.handle(forUserName: identity.userName)
      )
      let publicKey = privateKey.publicKey.derRepresentation
      let credentialId = WebAuthn.credentialId(publicKey: publicKey)
      let storedCredential = StoredPasskeyCredential(
        credentialId: credentialId.base64EncodedString(),
        relyingPartyIdentifier: identity.relyingPartyIdentifier,
        userName: identity.userName.passkeyDisplayName,
        userHandle: identity.userHandle.base64EncodedString(),
        privateKey: privateKey.rawRepresentation.base64EncodedString(),
        publicKey: publicKey.base64EncodedString(),
        createdAt: Date().timeIntervalSince1970,
        parentKeyId: parentKeyId
      )

      let authData = try WebAuthn.authenticatorDataForAttestation(
        relyingPartyIdentifier: identity.relyingPartyIdentifier,
        credentialId: credentialId,
        publicKey: publicKey
      )
      let registrationCredential = ASPasskeyRegistrationCredential(
        relyingParty: identity.relyingPartyIdentifier,
        clientDataHash: request.clientDataHash,
        credentialID: credentialId,
        attestationObject: WebAuthn.attestationObject(authenticatorData: authData)
      )

      try store.save(storedCredential)
      store.appendDiagnostic("stored passkey credential")

      Task {
        do {
          try await store.replaceIdentityStore()
          store.appendDiagnostic("replaceIdentityStore after registration succeeded")
        } catch {
          store.appendDiagnostic("replaceIdentityStore after registration failed: \(error.localizedDescription)")
        }
      }

      store.appendDiagnostic("completeRegistrationRequest")
      extensionContext.completeRegistrationRequest(using: registrationCredential) { [weak self] completed in
        self?.store?.appendDiagnostic("completeRegistrationRequest completion: \(completed)")
        self?.authContext = nil
      }
    } catch {
      store?.appendDiagnostic("registration error: \(error.localizedDescription)")
      showFailure(error.localizedDescription)
    }
  }

  private func completeAssertion(
    credential: StoredPasskeyCredential,
    clientDataHash: Data,
    relyingPartyIdentifier: String
  ) {
    do {
      let authenticatorData = WebAuthn.authenticatorDataForAssertion(
        relyingPartyIdentifier: relyingPartyIdentifier
      )
      let signature = try credential.sign(authenticatorData + clientDataHash)
      let assertionCredential = ASPasskeyAssertionCredential(
        userHandle: credential.userHandleData,
        relyingParty: relyingPartyIdentifier,
        signature: signature,
        clientDataHash: clientDataHash,
        authenticatorData: authenticatorData,
        credentialID: credential.credentialIdData
      )
      extensionContext.completeAssertionRequest(using: assertionCredential) { [weak self] _ in
        self?.authContext = nil
        self?.isCompletingAssertion = false
        self?.pendingAssertionCredential = nil
        self?.pendingAssertionClientDataHash = nil
        self?.pendingAssertionRelyingPartyIdentifier = nil
      }
    } catch {
      isCompletingAssertion = false
      cancel(code: .failed, message: error.localizedDescription)
    }
  }

  private func prepareAssertion(
    credential: StoredPasskeyCredential,
    clientDataHash: Data,
    relyingPartyIdentifier: String
  ) {
    pendingAssertionCredential = credential
    pendingAssertionClientDataHash = clientDataHash
    pendingAssertionRelyingPartyIdentifier = relyingPartyIdentifier
    showCheckingPasskeys()

    if hasPresentedInterface {
      DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
        self?.prepareTransactionPreviewOrAuthenticate()
      }
    }
  }

  private func prepareTransactionPreviewOrAuthenticate() {
    guard !isLoadingTransactionPreview, !isCompletingAssertion else {
      return
    }
    guard let credential = pendingAssertionCredential,
          credential.showTransactionRequests == true
    else {
      authenticateAndCompleteAssertion()
      return
    }
    guard let apiBaseUrl = credential.previewApiBaseUrl,
          let token = credential.previewToken,
          !token.isEmpty,
          let baseURL = URL(string: apiBaseUrl),
          baseURL.scheme?.lowercased() == "https",
          let encodedCredentialId = credential.credentialIdData.base64URLEncodedString()
            .addingPercentEncoding(withAllowedCharacters: .akitaURLPathComponent),
          let endpoint = URL(
            string: "/akita/passkey-previews/\(encodedCredentialId)",
            relativeTo: baseURL
          )?.absoluteURL
    else {
      cancel(code: .failed, message: "Transaction preview is required but is not configured.")
      return
    }

    isLoadingTransactionPreview = true
    showCheckingPasskeys()
    var request = URLRequest(url: endpoint)
    request.httpMethod = "GET"
    request.timeoutInterval = 15
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    request.setValue("application/json", forHTTPHeaderField: "Accept")

    URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
      DispatchQueue.main.async {
        guard let self else { return }
        self.isLoadingTransactionPreview = false
        do {
          if let error { throw error }
          guard let http = response as? HTTPURLResponse,
                (200..<300).contains(http.statusCode),
                let data
          else {
            throw TransactionPreviewError.unavailable
          }
          let envelope = try JSONDecoder().decode(TransactionPreviewEnvelope.self, from: data)
          try self.validateTransactionPreview(envelope.data, credential: credential)
          self.presentTransactionPreview(envelope.data)
        } catch {
          self.cancel(
            code: .failed,
            message: "The required transaction preview could not be verified: \(error.localizedDescription)"
          )
        }
      }
    }.resume()
  }

  private func validateTransactionPreview(
    _ preview: TransactionPreview,
    credential: StoredPasskeyCredential
  ) throws {
    guard preview.credentialId == credential.credentialIdData.base64URLEncodedString(),
          preview.expiresAt >= UInt64(Date().timeIntervalSince1970),
          preview.transactions.count > 0,
          preview.transactions.count <= 16,
          let expectedHash = pendingAssertionClientDataHash
    else {
      throw TransactionPreviewError.invalid
    }

    let escapedChallenge = try Self.jsonEscaped(preview.challenge)
    let escapedOrigin = try Self.jsonEscaped(preview.origin)
    let candidates = [
      "{\"type\":\"webauthn.get\",\"challenge\":\(escapedChallenge),\"origin\":\(escapedOrigin),\"crossOrigin\":false}",
      "{\"type\":\"webauthn.get\",\"challenge\":\(escapedChallenge),\"origin\":\(escapedOrigin)}",
    ]
    guard candidates.contains(where: {
      Data(SHA256.hash(data: Data($0.utf8))) == expectedHash
    }) else {
      throw TransactionPreviewError.challengeMismatch
    }
  }

  private func presentTransactionPreview(_ preview: TransactionPreview) {
    let lines = preview.transactions.enumerated().map { index, transaction in
      var detail = "\(index + 1). \(transaction.displayType)"
      detail += " from \(transaction.sender.abbreviatedAddress)"
      if let receiver = transaction.receiver, !receiver.isEmpty {
        detail += " to \(receiver.abbreviatedAddress)"
      }
      if let amount = transaction.amount, amount > 0 {
        detail += " · \(amount)"
      }
      if let appId = transaction.appId, appId > 0 {
        detail += " · app \(appId)"
      }
      if let assetId = transaction.assetId, assetId > 0 {
        detail += " · asset \(assetId)"
      }
      if let method = transaction.method, !method.isEmpty {
        detail += " · method \(method)"
      }
      detail += " · fee \(transaction.fee) µALGO"
      return detail
    }
    let alert = UIAlertController(
      title: "Approve transaction group?",
      message: lines.joined(separator: "\n"),
      preferredStyle: .alert
    )
    alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { [weak self] _ in
      self?.cancel(code: .userCanceled, message: "Transaction approval was canceled.")
    })
    alert.addAction(UIAlertAction(title: "Continue", style: .default) { [weak self] _ in
      self?.authenticateAndCompleteAssertion()
    })
    present(alert, animated: true)
  }

  private static func jsonEscaped(_ value: String) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: [value], options: [])
    guard let encoded = String(data: data, encoding: .utf8) else {
      throw TransactionPreviewError.invalid
    }
    return String(encoded.dropFirst().dropLast())
  }

  private func authenticateAndCompleteAssertion() {
    guard !isCompletingAssertion else {
      return
    }
    isCompletingAssertion = true

    guard let credential = pendingAssertionCredential,
          let clientDataHash = pendingAssertionClientDataHash,
          let relyingPartyIdentifier = pendingAssertionRelyingPartyIdentifier
    else {
      isCompletingAssertion = false
      cancel(code: .credentialIdentityNotFound, message: "Credential identity not found.")
      return
    }

    let context = LAContext()
    authContext = context
    context.localizedCancelTitle = "Cancel"
    context.localizedFallbackTitle = ""

    let policy: LAPolicy = .deviceOwnerAuthentication

    var error: NSError?
    guard context.canEvaluatePolicy(policy, error: &error) else {
      authContext = nil
      isCompletingAssertion = false
      showFailure(error?.localizedDescription ?? "Device authentication is not available.")
      return
    }

    store?.appendDiagnostic("evaluatePolicy assertion start")
    context.evaluatePolicy(policy, localizedReason: "Use passkeys with Akita") { [weak self] success, authenticationError in
      DispatchQueue.main.async {
        guard let self else {
          return
        }

        if success {
          self.store?.appendDiagnostic("evaluatePolicy assertion success")
          self.completeAssertion(
            credential: credential,
            clientDataHash: clientDataHash,
            relyingPartyIdentifier: relyingPartyIdentifier
          )
        } else {
          self.authContext = nil
          self.isCompletingAssertion = false
          self.store?.appendDiagnostic(
            "evaluatePolicy assertion failed: \(authenticationError?.localizedDescription ?? "unknown")"
          )
          self.cancel(
            code: .userCanceled,
            message: authenticationError?.localizedDescription ?? "Biometric authentication was canceled."
          )
        }
      }
    }
  }

  private func cancel(code: ASExtensionError.Code, message: String) {
    store?.appendDiagnostic("cancel: \(message)")
    extensionContext.cancelRequest(
      withError: NSError(
        domain: ASExtensionErrorDomain,
        code: code.rawValue,
        userInfo: [NSLocalizedDescriptionKey: message]
      )
    )
  }

  private func configureView() {
    view.backgroundColor = .systemBackground

    activityIndicator.hidesWhenStopped = true
    activityIndicator.startAnimating()

    statusLabel.text = "checking passkeys..."
    statusLabel.font = .preferredFont(forTextStyle: .body)
    statusLabel.textColor = .secondaryLabel
    statusLabel.textAlignment = .center
    statusLabel.numberOfLines = 0
    statusLabel.adjustsFontForContentSizeCategory = true

    let stack = UIStackView(arrangedSubviews: [activityIndicator, statusLabel])
    stack.axis = .vertical
    stack.alignment = .center
    stack.spacing = 14
    stack.translatesAutoresizingMaskIntoConstraints = false

    view.addSubview(stack)
    NSLayoutConstraint.activate([
      stack.leadingAnchor.constraint(equalTo: view.layoutMarginsGuide.leadingAnchor),
      stack.trailingAnchor.constraint(equalTo: view.layoutMarginsGuide.trailingAnchor),
      stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
    ])
  }

  private func showCheckingPasskeys() {
    activityIndicator.startAnimating()
    statusLabel.text = "checking passkeys..."
  }

  private func showFailure(_ message: String) {
    store?.appendDiagnostic("showFailure: \(message)")
    activityIndicator.stopAnimating()
    statusLabel.text = message
  }

  private func authenticateAndCompleteRegistration() {
    guard !isCompletingRegistration else {
      return
    }
    isCompletingRegistration = true

    let context = LAContext()
    authContext = context
    context.localizedCancelTitle = "Cancel"
    context.localizedFallbackTitle = ""

    let policy: LAPolicy = .deviceOwnerAuthentication

    var error: NSError?
    guard context.canEvaluatePolicy(policy, error: &error) else {
      authContext = nil
      showFailure(error?.localizedDescription ?? "Device authentication is not available.")
      return
    }

    store?.appendDiagnostic("evaluatePolicy start")
    context.evaluatePolicy(policy, localizedReason: "Create passkeys with Akita") { [weak self] success, authenticationError in
      DispatchQueue.main.async {
        guard let self else {
          return
        }

        if success {
          self.store?.appendDiagnostic("evaluatePolicy success")
          self.completePendingRegistration()
        } else {
          self.authContext = nil
          self.store?.appendDiagnostic(
            "evaluatePolicy failed: \(authenticationError?.localizedDescription ?? "unknown")"
          )
          self.cancel(
            code: .userCanceled,
            message: authenticationError?.localizedDescription ?? "Biometric authentication was canceled."
          )
        }
      }
    }
  }
}

private struct TransactionPreviewEnvelope: Decodable {
  let data: TransactionPreview
}

private struct TransactionPreview: Decodable {
  let credentialId: String
  let challenge: String
  let origin: String
  let transactions: [TransactionPreviewTransaction]
  let expiresAt: UInt64
}

private struct TransactionPreviewTransaction: Decodable {
  let type: String
  let sender: String
  let receiver: String?
  let amount: UInt64?
  let assetId: UInt64?
  let appId: UInt64?
  let method: String?
  let fee: UInt64

  var displayType: String {
    switch type {
    case "pay": return "Payment"
    case "axfer": return "Asset transfer"
    case "appl": return "Application call"
    default: return type
    }
  }
}

private enum TransactionPreviewError: LocalizedError {
  case unavailable
  case invalid
  case challengeMismatch

  var errorDescription: String? {
    switch self {
    case .unavailable: return "No preview is available."
    case .invalid: return "The preview is invalid or expired."
    case .challengeMismatch: return "The preview does not match this passkey request."
    }
  }
}

private extension CharacterSet {
  static let akitaURLPathComponent = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
}

private extension String {
  var abbreviatedAddress: String {
    count > 16 ? "\(prefix(7))…\(suffix(5))" : self
  }
}
