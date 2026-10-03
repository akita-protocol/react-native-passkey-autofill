import AuthenticationServices
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import UIKit

/// Everything a registration needs, captured once when the request arrives.
private struct RegistrationRequestSnapshot {
  let request: ASPasskeyCredentialRequest
  let identity: ASPasskeyCredentialIdentity
  let prfInput: PrfInput?
}

/// Everything an assertion needs, captured once when the request arrives and
/// never mutated: the credential (metadata only — its key is opened after the
/// user is verified), its transaction-preview policy, the client data hash the
/// preview is checked against and the signature covers, and the PRF salts.
private struct AssertionRequestSnapshot {
  let credential: StoredPasskeyCredential
  let clientDataHash: Data
  let relyingPartyIdentifier: String
  let prfInput: PrfInput?
}

private enum CredentialOperationPayload {
  case registration(RegistrationRequestSnapshot)
  case assertion(AssertionRequestSnapshot)

  var kind: PendingCredentialOperationKind {
    switch self {
    case .registration:
      return .registration
    case .assertion(let request):
      switch request.credential.transactionPreviewPolicy {
      case .never:
        return .assertion(requiresPreview: false)
      case .required:
        return .assertion(requiresPreview: true)
      }
    }
  }
}

private struct CredentialOperationResources {
  var delayedStart: DispatchWorkItem?
  var authenticationContext: LAContext?
  var transactionPreviewSession: URLSession?
  var transactionPreviewTask: URLSessionDataTask?
  var transactionPreviewAlert: UIAlertController?
  var identityStoreTask: Task<Void, Never>?
}

private typealias CredentialOperation = PendingCredentialOperation<
  CredentialOperationPayload,
  CredentialOperationResources
>

final class CredentialProviderViewController: ASCredentialProviderViewController {
  private let store = PasskeyCredentialStore()
  private var pendingOperation: CredentialOperation?
  private var hasPresentedInterface = false
  private let activityIndicator = UIActivityIndicatorView(style: .large)
  private let statusLabel = UILabel()

  deinit {
    retireCurrentOperation()
  }

  override func viewDidLoad() {
    super.viewDidLoad()
    configureView()
  }

  override func viewDidAppear(_ animated: Bool) {
    super.viewDidAppear(animated)
    hasPresentedInterface = true
    scheduleStartForCurrentOperation()
  }

  override func viewDidDisappear(_ animated: Bool) {
    super.viewDidDisappear(animated)
    hasPresentedInterface = false
    if view.window != nil,
       let alert = pendingOperation?.resources.transactionPreviewAlert,
       presentedViewController === alert {
      return
    }
    terminateCurrentOperationForLifecycle()
  }

  override func prepareCredentialList(
    for serviceIdentifiers: [ASCredentialServiceIdentifier],
    requestParameters: ASPasskeyCredentialRequestParameters
  ) {
    supersedeCurrentOperation()

    guard #available(iOSApplicationExtension 17.0, *) else {
      cancelRequestWithoutOperation(code: .failed, message: "Passkeys require iOS 17 or newer.")
      return
    }

    let relyingPartyIdentifier = requestParameters.relyingPartyIdentifier
    let allowedCredentials = Set(requestParameters.allowedCredentials.map { $0.base64URLEncodedString() })
    guard let credential = store?.credentials(
      relyingPartyIdentifier: relyingPartyIdentifier
    ).first(where: {
      allowedCredentials.isEmpty || allowedCredentials.contains($0.credentialIdData.base64URLEncodedString())
    }) else {
      cancelRequestWithoutOperation(code: .credentialIdentityNotFound, message: "No passkey is available.")
      return
    }

    beginAssertion(
      credential: credential,
      clientDataHash: requestParameters.clientDataHash,
      relyingPartyIdentifier: relyingPartyIdentifier,
      prfInput: Self.prfInput(fromAssertion: requestParameters)
    )
  }

  override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
    supersedeCurrentOperation()

    guard #available(iOSApplicationExtension 17.0, *),
          let request = credentialRequest as? ASPasskeyCredentialRequest
    else {
      cancelRequestWithoutOperation(code: .failed, message: "Unsupported credential request.")
      return
    }

    guard request.credentialIdentity is ASPasskeyCredentialIdentity else {
      cancelRequestWithoutOperation(
        code: .credentialIdentityNotFound,
        message: "Credential identity not found."
      )
      return
    }

    cancelRequestWithoutOperation(
      code: .userInteractionRequired,
      message: "User verification is required."
    )
  }

  override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
    supersedeCurrentOperation()

    guard #available(iOSApplicationExtension 17.0, *),
          let request = credentialRequest as? ASPasskeyCredentialRequest
    else {
      cancelRequestWithoutOperation(code: .failed, message: "Unsupported credential request.")
      return
    }

    guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity,
          let credential = store?.credential(id: identity.credentialID)
    else {
      cancelRequestWithoutOperation(
        code: .credentialIdentityNotFound,
        message: "Credential identity not found."
      )
      return
    }

    beginAssertion(
      credential: credential,
      clientDataHash: request.clientDataHash,
      relyingPartyIdentifier: identity.relyingPartyIdentifier,
      prfInput: Self.prfInput(fromAssertion: request)
    )
  }

  override func prepareInterface(forPasskeyRegistration request: ASCredentialRequest) {
    supersedeCurrentOperation()
    store?.appendDiagnostic("prepareInterface(forPasskeyRegistration)")

    guard #available(iOSApplicationExtension 17.0, *),
          let request = request as? ASPasskeyCredentialRequest,
          let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
    else {
      cancelRequestWithoutOperation(
        code: .failed,
        message: "Unsupported passkey registration request."
      )
      return
    }

    beginOperation(
      payload: .registration(
        RegistrationRequestSnapshot(
          request: request,
          identity: identity,
          prfInput: Self.prfInput(fromRegistration: request)
        )
      )
    )
  }

  override func prepareInterfaceForExtensionConfiguration() {
    supersedeCurrentOperation()
    extensionContext.completeExtensionConfigurationRequest()
  }

  private func beginAssertion(
    credential: StoredPasskeyCredential,
    clientDataHash: Data,
    relyingPartyIdentifier: String,
    prfInput: PrfInput?
  ) {
    let request = AssertionRequestSnapshot(
      credential: credential,
      clientDataHash: clientDataHash,
      relyingPartyIdentifier: relyingPartyIdentifier,
      prfInput: prfInput
    )
    beginOperation(payload: .assertion(request))
  }

  private func beginOperation(payload: CredentialOperationPayload) {
    retireCurrentOperation()
    pendingOperation = CredentialOperation(
      kind: payload.kind,
      payload: payload,
      resources: CredentialOperationResources()
    )
    showCheckingPasskeys()
    scheduleStartForCurrentOperation()
  }

  private func scheduleStartForCurrentOperation() {
    guard hasPresentedInterface,
          let operation = pendingOperation,
          operation.phase == .waiting,
          operation.resources.delayedStart == nil
    else {
      return
    }

    let operationID = operation.id
    let workItem = DispatchWorkItem { [weak self] in
      self?.startWaitingOperation(operationID: operationID)
    }
    guard updateOperationResources(
      operationID: operationID,
      phase: .waiting,
      { $0.delayedStart = workItem }
    ) else {
      workItem.cancel()
      return
    }

    DispatchQueue.main.asyncAfter(deadline: .now() + 0.25, execute: workItem)
  }

  private func startWaitingOperation(operationID: UUID) {
    guard let payload = payload(operationID: operationID, phase: .waiting) else {
      return
    }

    switch payload {
    case .registration:
      authenticate(operationID: operationID, from: .waiting)
    case .assertion(let request):
      switch request.credential.transactionPreviewPolicy {
      case .never:
        authenticate(operationID: operationID, from: .waiting)
      case .required(let httpsEndpoint, let token):
        fetchRequiredTransactionPreview(
          request,
          operationID: operationID,
          httpsEndpoint: httpsEndpoint,
          token: token
        )
      }
    }
  }

  private func fetchRequiredTransactionPreview(
    _ assertionRequest: AssertionRequestSnapshot,
    operationID: UUID,
    httpsEndpoint: URL,
    token: String
  ) {
    guard transitionOperation(
      operationID: operationID,
      from: .waiting,
      to: .loadingPreview
    ) else {
      return
    }
    guard let encodedCredentialId = assertionRequest.credential.credentialIdData
      .base64URLEncodedString()
      .addingPercentEncoding(withAllowedCharacters: .akitaURLPathComponent),
      let endpoint = URL(
        string: "/akita/passkey-previews/\(encodedCredentialId)",
        relativeTo: httpsEndpoint
      )?.absoluteURL
    else {
      cancelOperation(
        operationID: operationID,
        code: .failed,
        message: "The required transaction preview endpoint is invalid."
      )
      return
    }

    showCheckingPasskeys()
    var previewRequest = URLRequest(url: endpoint)
    previewRequest.httpMethod = "GET"
    previewRequest.timeoutInterval = 15
    previewRequest.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    previewRequest.setValue("application/json", forHTTPHeaderField: "Accept")

    let configuration = URLSessionConfiguration.ephemeral
    configuration.httpShouldSetCookies = false
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    configuration.urlCache = nil
    let session = URLSession(
      configuration: configuration,
      delegate: RejectingRedirectSessionDelegate(),
      delegateQueue: nil
    )
    let task = session.dataTask(with: previewRequest) { [weak self] data, response, error in
      DispatchQueue.main.async {
        guard let self,
              self.isCurrentOperation(
                operationID: operationID,
                phase: .loadingPreview
              )
        else {
          return
        }

        do {
          if let error {
            throw error
          }
          guard let http = response as? HTTPURLResponse,
                (200..<300).contains(http.statusCode),
                let data
          else {
            throw TransactionPreviewError.unavailable
          }
          let envelope = try JSONDecoder().decode(TransactionPreviewEnvelope.self, from: data)
          try self.validateTransactionPreview(envelope.data, request: assertionRequest)
          self.presentTransactionPreview(
            envelope.data,
            request: assertionRequest,
            operationID: operationID
          )
        } catch {
          self.cancelOperation(
            operationID: operationID,
            code: .failed,
            message: "The required transaction preview could not be verified: \(error.localizedDescription)"
          )
        }
      }
    }
    guard updateOperationResources(
      operationID: operationID,
      phase: .loadingPreview,
      {
        $0.transactionPreviewSession = session
        $0.transactionPreviewTask = task
      }
    ) else {
      task.cancel()
      session.invalidateAndCancel()
      return
    }
    task.resume()
  }

  private func validateTransactionPreview(
    _ preview: TransactionPreview,
    request: AssertionRequestSnapshot
  ) throws {
    guard preview.credentialId == request.credential.credentialIdData.base64URLEncodedString(),
          preview.expiresAt >= UInt64(Date().timeIntervalSince1970),
          preview.transactions.count > 0,
          preview.transactions.count <= 16
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
      Data(SHA256.hash(data: Data($0.utf8))) == request.clientDataHash
    }) else {
      throw TransactionPreviewError.challengeMismatch
    }
  }

  private func presentTransactionPreview(
    _ preview: TransactionPreview,
    request: AssertionRequestSnapshot,
    operationID: UUID
  ) {
    guard transitionOperation(
      operationID: operationID,
      from: .loadingPreview,
      to: .presentingPreview
    ) else {
      return
    }

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
      guard let self,
            self.isCurrentOperation(
              operationID: operationID,
              phase: .presentingPreview
            )
      else {
        return
      }
      self.cancelOperation(
        operationID: operationID,
        code: .userCanceled,
        message: "Transaction approval was canceled."
      )
    })
    alert.addAction(UIAlertAction(title: "Continue", style: .default) { [weak self] _ in
      guard let self else {
        return
      }
      self.authenticate(operationID: operationID, from: .presentingPreview)
    })
    guard updateOperationResources(
      operationID: operationID,
      phase: .presentingPreview,
      { $0.transactionPreviewAlert = alert }
    ) else {
      alert.dismiss(animated: false)
      return
    }
    present(alert, animated: true)
  }

  private func authenticate(
    operationID: UUID,
    from expectedPhase: PendingCredentialOperationPhase
  ) {
    guard transitionOperation(
      operationID: operationID,
      from: expectedPhase,
      to: .authenticating
    ), let payload = payload(operationID: operationID, phase: .authenticating) else {
      return
    }

    let context = LAContext()
    context.localizedCancelTitle = "Cancel"
    context.localizedFallbackTitle = ""
    guard updateOperationResources(
      operationID: operationID,
      phase: .authenticating,
      { $0.authenticationContext = context }
    ) else {
      context.invalidate()
      return
    }

    let policy: LAPolicy = BiometricRequirement.current.laPolicy
    var error: NSError?
    guard context.canEvaluatePolicy(policy, error: &error) else {
      cancelOperation(
        operationID: operationID,
        code: .failed,
        message: error?.localizedDescription ?? "Device authentication is not available."
      )
      return
    }

    let reason: String
    switch payload {
    case .registration:
      reason = "Create passkeys with Akita"
      store?.appendDiagnostic("evaluatePolicy registration start")
    case .assertion:
      reason = "Use passkeys with Akita"
      store?.appendDiagnostic("evaluatePolicy assertion start")
    }

    context.evaluatePolicy(policy, localizedReason: reason) { [weak self] success, authenticationError in
      DispatchQueue.main.async {
        guard let self,
              self.isCurrentOperation(
                operationID: operationID,
                phase: .authenticating
              )
        else {
          return
        }

        if success {
          switch payload {
          case .registration(let request):
            self.store?.appendDiagnostic("evaluatePolicy registration success")
            self.completeRegistration(request, operationID: operationID)
          case .assertion(let request):
            self.store?.appendDiagnostic("evaluatePolicy assertion success")
            self.completeAssertion(request, operationID: operationID)
          }
        } else {
          self.store?.appendDiagnostic(
            "evaluatePolicy failed: \(authenticationError?.localizedDescription ?? "unknown")"
          )
          self.cancelOperation(
            operationID: operationID,
            code: .userCanceled,
            message: authenticationError?.localizedDescription ?? "Device authentication was canceled."
          )
        }
      }
    }
  }

  private func completeRegistration(
    _ snapshot: RegistrationRequestSnapshot,
    operationID: UUID
  ) {
    guard transitionOperation(
      operationID: operationID,
      from: .authenticating,
      to: .completing
    ) else {
      return
    }
    store?.appendDiagnostic("completeRegistration")

    do {
      guard let store else {
        cancelOperation(
          operationID: operationID,
          code: .failed,
          message: "Wallet root key is not available. Open Akita once, unlock it, then try again."
        )
        return
      }

      // No requested scheme: a new credential takes the preferred parent (the
      // wallet's HD root when Akita shared one, otherwise the deterministic-P256
      // main key) and records which one it got, so every later assertion
      // re-derives against the same root.
      let parent = try store.parentSecret()
      let identity = snapshot.identity
      let userHandle = identity.userHandleString
      let privateKey: P256.Signing.PrivateKey
      if parent.scheme == PasskeyKeystoreRecords.schemeAkitaHdRoot {
        // Akita site passkeys: the shared derivation every Akita platform
        // reproduces (test-vectors/site-credential-vectors.json).
        privateKey = try SiteCredentialDerivation.privateKey(
          rootSecret: parent.bytes,
          rpId: identity.relyingPartyIdentifier,
          handle: SiteCredentialDerivation.handle(forUserName: identity.userName)
        )
      } else {
        privateKey = try Self.domainSpecificKeyPair(
          derivedParentSecret: parent.bytes,
          origin: identity.relyingPartyIdentifier,
          userHandle: userHandle.lowercased()
        )
      }
      let publicKey = privateKey.publicKey.derRepresentation
      let credentialId = WebAuthn.credentialId(publicKey: publicKey)
      // Derivation is deterministic: registering the same account again yields
      // the same credential id. Refuse it (WebAuthn InvalidStateError) — whether
      // the relying party listed it in excludeCredentials or it is already stored
      // here — so an existing passkey, and its preview policy, is never replaced.
      if Self.excludedCredentialIds(snapshot.request).contains(credentialId)
        || store.hasCredentialRecord(id: credentialId)
      {
        cancelOperation(
          operationID: operationID,
          code: Self.existingCredentialErrorCode,
          message: "A passkey for this account already exists."
        )
        return
      }
      let storedCredential = StoredPasskeyCredential(
        credentialId: credentialId.base64EncodedString(),
        relyingPartyIdentifier: identity.relyingPartyIdentifier,
        userName: identity.userName.passkeyDisplayName,
        userHandle: identity.userHandle.base64EncodedString(),
        privateKey: privateKey.rawRepresentation.base64EncodedString(),
        publicKey: publicKey.base64EncodedString(),
        createdAt: Date().timeIntervalSince1970,
        lastUsedAt: nil,
        parentKeyId: parent.keyId,
        derivationScheme: parent.scheme
      )

      let authenticatorData = try WebAuthn.authenticatorDataForAttestation(
        relyingPartyIdentifier: identity.relyingPartyIdentifier,
        credentialId: credentialId,
        publicKey: publicKey
      )
      let registrationCredential = ASPasskeyRegistrationCredential(
        relyingParty: identity.relyingPartyIdentifier,
        clientDataHash: snapshot.request.clientDataHash,
        credentialID: credentialId,
        attestationObject: WebAuthn.attestationObject(authenticatorData: authenticatorData)
      )
      attachPrfRegistrationOutput(
        to: registrationCredential,
        derivedParentSecret: parent.bytes,
        relyingPartyIdentifier: identity.relyingPartyIdentifier,
        userHandle: userHandle
      )

      try store.save(storedCredential)
      store.appendDiagnostic("stored passkey credential")

      let identityStoreTask = Task { @MainActor [weak self, store] in
        guard !Task.isCancelled else {
          return
        }
        do {
          try await store.replaceIdentityStore()
          guard !Task.isCancelled,
                let self,
                self.isCurrentOperation(
                  operationID: operationID,
                  phase: .completing
                )
          else {
            return
          }
          store.appendDiagnostic("replaceIdentityStore after registration succeeded")
        } catch {
          guard !Task.isCancelled,
                let self,
                self.isCurrentOperation(
                  operationID: operationID,
                  phase: .completing
                )
          else {
            return
          }
          store.appendDiagnostic(
            "replaceIdentityStore after registration failed; continuing with saved credential: \(error.localizedDescription)"
          )
        }
      }
      guard updateOperationResources(
        operationID: operationID,
        phase: .completing,
        { $0.identityStoreTask = identityStoreTask }
      ) else {
        identityStoreTask.cancel()
        return
      }
      submitRegistrationToApple(
        registrationCredential,
        snapshot: snapshot,
        operationID: operationID
      )
    } catch PasskeyCredentialStoreError.credentialAlreadyExists {
      cancelOperation(
        operationID: operationID,
        code: Self.existingCredentialErrorCode,
        message: "A passkey for this account already exists."
      )
    } catch {
      cancelOperation(
        operationID: operationID,
        code: .failed,
        message: error.localizedDescription
      )
    }
  }

  /// The credential ids the relying party asked not to re-register.
  private static func excludedCredentialIds(_ request: ASPasskeyCredentialRequest) -> Set<Data> {
    if #available(iOSApplicationExtension 18.0, *) {
      return Set((request.excludedCredentials ?? []).map(\.credentialID))
    }
    return []
  }

  /// Surfaces to the relying party as WebAuthn's InvalidStateError where iOS
  /// supports it.
  private static var existingCredentialErrorCode: ASExtensionError.Code {
    if #available(iOSApplicationExtension 18.0, *) {
      return .matchedExcludedCredential
    }
    return .failed
  }

  private func submitRegistrationToApple(
    _ credential: ASPasskeyRegistrationCredential,
    snapshot: RegistrationRequestSnapshot,
    operationID: UUID
  ) {
    guard isCurrentOperation(operationID: operationID, phase: .completing) else {
      return
    }
    store?.appendDiagnostic("completeRegistrationRequest")
    extensionContext.completeRegistrationRequest(using: credential) { [weak self, snapshot, credential] completed in
      DispatchQueue.main.async {
        _ = (snapshot, credential)
        guard let self,
              self.isCurrentOperation(
                operationID: operationID,
                phase: .completing
              )
        else {
          return
        }
        self.store?.appendDiagnostic("completeRegistrationRequest completion: \(completed)")
        self.finishSuccessfulOperation(operationID: operationID)
      }
    }
  }

  private func completeAssertion(
    _ request: AssertionRequestSnapshot,
    operationID: UUID
  ) {
    guard transitionOperation(
      operationID: operationID,
      from: .authenticating,
      to: .completing
    ) else {
      return
    }

    // The snapshot's credential was selected from the metadata-only list. Its
    // private key is opened here, after the user was verified, for this one
    // record only — and only if it still carries the very preview policy the
    // snapshot was gated on.
    guard let signingCredential = store?.signingCredential(id: request.credential.credentialIdData),
          signingCredential.transactionPreviewPolicy == request.credential.transactionPreviewPolicy
    else {
      cancelOperation(
        operationID: operationID,
        code: .credentialIdentityNotFound,
        message: "Credential not found."
      )
      return
    }

    do {
      let authenticatorData = WebAuthn.authenticatorDataForAssertion(
        relyingPartyIdentifier: request.relyingPartyIdentifier
      )
      let signature = try signingCredential.sign(authenticatorData + request.clientDataHash)
      let assertionCredential = ASPasskeyAssertionCredential(
        userHandle: request.credential.userHandleData,
        relyingParty: request.relyingPartyIdentifier,
        signature: signature,
        clientDataHash: request.clientDataHash,
        authenticatorData: authenticatorData,
        credentialID: request.credential.credentialIdData
      )
      attachPrfAssertionOutput(
        to: assertionCredential,
        credential: request.credential,
        relyingPartyIdentifier: request.relyingPartyIdentifier,
        prfInput: request.prfInput
      )

      extensionContext.completeAssertionRequest(using: assertionCredential) { [weak self, request, assertionCredential] completed in
        DispatchQueue.main.async {
          _ = (request, assertionCredential)
          guard let self,
                self.isCurrentOperation(
                  operationID: operationID,
                  phase: .completing
                )
          else {
            return
          }
          self.store?.appendDiagnostic("completeAssertionRequest completion: \(completed)")
          self.store?.recordCredentialUsage(id: request.credential.credentialId)
          self.finishSuccessfulOperation(operationID: operationID)
        }
      }
    } catch {
      cancelOperation(
        operationID: operationID,
        code: .failed,
        message: error.localizedDescription
      )
    }
  }

  private func transitionOperation(
    operationID: UUID,
    from expectedPhase: PendingCredentialOperationPhase,
    to nextPhase: PendingCredentialOperationPhase
  ) -> Bool {
    pendingOperation?.transition(
      operationID: operationID,
      from: expectedPhase,
      to: nextPhase
    ) == true
  }

  private func updateOperationResources(
    operationID: UUID,
    phase expectedPhase: PendingCredentialOperationPhase? = nil,
    _ update: (inout CredentialOperationResources) -> Void
  ) -> Bool {
    guard pendingOperation?.id == operationID,
          expectedPhase.map({ pendingOperation?.phase == $0 }) ?? true,
          pendingOperation?.phase != .terminal
    else {
      return false
    }
    update(&pendingOperation!.resources)
    return true
  }

  private func isCurrentOperation(
    operationID: UUID,
    phase expectedPhase: PendingCredentialOperationPhase? = nil
  ) -> Bool {
    guard pendingOperation?.id == operationID else {
      return false
    }
    return expectedPhase.map { pendingOperation?.phase == $0 } ?? true
  }

  @discardableResult
  private func retireOperation(operationID: UUID) -> Bool {
    guard var operation = pendingOperation,
          operation.terminate(operationID: operationID)
    else {
      return false
    }
    pendingOperation = nil
    Self.cleanupResources(operation.resources)
    return true
  }

  @discardableResult
  private func retireCurrentOperation() -> Bool {
    guard let operationID = pendingOperation?.id else {
      return false
    }
    return retireOperation(operationID: operationID)
  }

  private func payload(
    operationID: UUID,
    phase expectedPhase: PendingCredentialOperationPhase
  ) -> CredentialOperationPayload? {
    guard isCurrentOperation(
      operationID: operationID,
      phase: expectedPhase
    ) else {
      return nil
    }
    return pendingOperation?.payload
  }

  private func finishSuccessfulOperation(operationID: UUID) {
    retireOperation(operationID: operationID)
  }

  private func cancelOperation(
    operationID: UUID,
    code: ASExtensionError.Code,
    message: String
  ) {
    guard retireOperation(operationID: operationID) else {
      return
    }
    cancelExtensionRequest(code: code, message: message)
  }

  private func supersedeCurrentOperation() {
    retireCurrentOperation()
  }

  private func terminateCurrentOperationForLifecycle() {
    retireCurrentOperation()
  }

  private static func cleanupResources(_ resources: CredentialOperationResources) {
    resources.delayedStart?.cancel()
    resources.transactionPreviewTask?.cancel()
    resources.transactionPreviewSession?.invalidateAndCancel()
    resources.transactionPreviewAlert?.dismiss(animated: false)
    resources.authenticationContext?.invalidate()
    resources.identityStoreTask?.cancel()
  }

  private func cancelRequestWithoutOperation(
    code: ASExtensionError.Code,
    message: String
  ) {
    cancelExtensionRequest(code: code, message: message)
  }

  private func cancelExtensionRequest(
    code: ASExtensionError.Code,
    message: String
  ) {
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

  private static func jsonEscaped(_ value: String) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: [value], options: [])
    guard let encoded = String(data: data, encoding: .utf8) else {
      throw TransactionPreviewError.invalid
    }
    return String(encoded.dropFirst().dropLast())
  }

  private static func domainSpecificKeyPair(
    derivedParentSecret: Data,
    origin: String,
    userHandle: String,
    counter: UInt32 = 0
  ) throws -> P256.Signing.PrivateKey {
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
        return key
      }
    }

    throw PasskeyCredentialStoreError.invalidPrivateKey
  }
}

private final class RejectingRedirectSessionDelegate: NSObject, URLSessionTaskDelegate {
  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest,
    completionHandler: @escaping (URLRequest?) -> Void
  ) {
    completionHandler(nil)
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

private extension ASPasskeyCredentialIdentity {
  var userHandleString: String {
    String(data: userHandle, encoding: .utf8) ?? userHandle.base64URLEncodedString()
  }
}

// MARK: - PRF extension helpers

extension CredentialProviderViewController {
  /// Extract PRF inputs from a passkey assertion request. The platform passes
  /// the RP-supplied salts down to credential providers via `extensionInput`
  /// (iOS 17.4+ for the type itself, iOS 18+ for the `prf` property).
  static func prfInput(fromAssertion request: ASPasskeyCredentialRequest) -> PrfInput? {
    if #available(iOSApplicationExtension 18.0, *) {
      guard case let .assertion(input) = request.extensionInput,
            let prf = input.prf else { return nil }
      return prfInput(fromAssertionInput: prf)
    }
    return nil
  }

  /// Variant for the `prepareCredentialList` flow which gives us the
  /// `ASPasskeyCredentialRequestParameters` directly.
  static func prfInput(fromAssertion parameters: ASPasskeyCredentialRequestParameters) -> PrfInput? {
    if #available(iOSApplicationExtension 18.0, *) {
      guard let prf = parameters.extensionInput?.prf else { return nil }
      return prfInput(fromAssertionInput: prf)
    }
    return nil
  }

  /// Extract PRF inputs from a passkey registration request. Most relying
  /// parties only set `prf.enabled` on create, but a few also pass eval salts
  /// to immediately derive a secret.
  static func prfInput(fromRegistration request: ASPasskeyCredentialRequest) -> PrfInput? {
    if #available(iOSApplicationExtension 18.0, *) {
      guard case let .registration(input) = request.extensionInput,
            let prf = input.prf else { return nil }
      return prfInput(fromRegistrationInput: prf)
    }
    return nil
  }

  @available(iOSApplicationExtension 18.0, *)
  private static func prfInput(
    fromAssertionInput prf: ASAuthorizationPublicKeyCredentialPRFAssertionInput
  ) -> PrfInput? {
    // `inputValues` (when present) overrides `saltInput1/2` per WebAuthn's
    // `evalByCredential` semantics. The platform exposes whichever is
    // applicable to the credential the user actually picked.
    if let values = prf.inputValues {
      return PrfInput(first: values.saltInput1, second: values.saltInput2)
    }
    return nil
  }

  @available(iOSApplicationExtension 18.0, *)
  private static func prfInput(
    fromRegistrationInput prf: ASAuthorizationPublicKeyCredentialPRFRegistrationInput
  ) -> PrfInput? {
    if let values = prf.inputValues {
      return PrfInput(first: values.saltInput1, second: values.saltInput2)
    }
    return nil
  }

  /// Compute and attach PRF outputs to an assertion credential. No-op on
  /// pre-iOS 18 systems, and a no-op when the RP did not supply PRF inputs.
  func attachPrfAssertionOutput(
    to assertionCredential: ASPasskeyAssertionCredential,
    credential: StoredPasskeyCredential,
    relyingPartyIdentifier: String,
    prfInput: PrfInput?
  ) {
    guard #available(iOSApplicationExtension 18.0, *),
          let input = prfInput else { return }

    do {
      guard let store else { return }
      // PRF is recomputed from the parent secret on EVERY assertion, so it must
      // use the very parent this credential was created against — an unstamped
      // credential predates the dp256 main key and is pinned to the BIP32 root.
      let parent = try store.parentSecret(
        scheme: credential.derivationScheme ?? PasskeyKeystoreRecords.schemeBip32Ed25519
      )
      let userHandle = credential.userHandle
      let credRandom = Prf.credRandom(
        hdRootSecret: parent.bytes,
        relyingPartyIdentifier: relyingPartyIdentifier,
        userHandle: userHandle
      )
      let first = SymmetricKey(data: Prf.evaluate(credRandom: credRandom, salt: input.first))
      let second = input.second.map { SymmetricKey(data: Prf.evaluate(credRandom: credRandom, salt: $0)) }
      let prfOutput = ASAuthorizationPublicKeyCredentialPRFAssertionOutput(
        first: first,
        second: second
      )
      assertionCredential.extensionOutput = ASPasskeyAssertionCredentialExtensionOutput(prf: prfOutput)
      store.appendDiagnostic("attached PRF assertion output")
    } catch {
      store?.appendDiagnostic("failed to attach PRF assertion output: \(error.localizedDescription)")
    }
  }

  /// Attach PRF output to a registration credential.
  ///
  /// Per the agreed scope, we always advertise `prf.enabled = true` on
  /// registration to signal the credential supports PRF. If the RP also sent
  /// eval salts we still defer the actual evaluation to a follow-up assertion
  /// (matching the behaviour of most platform authenticators).
  func attachPrfRegistrationOutput(
    to registrationCredential: ASPasskeyRegistrationCredential,
    derivedParentSecret: Data,
    relyingPartyIdentifier: String,
    userHandle: String
  ) {
    guard #available(iOSApplicationExtension 18.0, *) else { return }
    let prfOutput = ASAuthorizationPublicKeyCredentialPRFRegistrationOutput.supported
    registrationCredential.extensionOutput = ASPasskeyRegistrationCredentialExtensionOutput(prf: prfOutput)
    store?.appendDiagnostic("attached PRF registration output (enabled)")
  }
}
