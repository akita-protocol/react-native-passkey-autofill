import Foundation

private final class CleanupProbe {
  var delayedStartCancellations = 0
  var previewTaskCancellations = 0
  var previewSessionCancellations = 0
  var alertDismissals = 0
  var authenticationInvalidations = 0
  var identityStoreTaskCancellations = 0
}

private struct FakeResources {
  let probe: CleanupProbe
}

private enum FakePayload: Equatable {
  case registration(String)
  case assertion(String)
}

private struct HarnessDriver {
  private(set) var current: PendingCredentialOperation<FakePayload, FakeResources>?
  private(set) var terminalCallbacks: [UUID: Int] = [:]

  mutating func begin(
    id: UUID,
    kind: PendingCredentialOperationKind,
    payload: FakePayload,
    probe: CleanupProbe = CleanupProbe()
  ) -> CleanupProbe {
    if let replaced = takeCurrentToTerminal() {
      cleanup(replaced)
    }
    current = PendingCredentialOperation(
      id: id,
      kind: kind,
      payload: payload,
      resources: FakeResources(probe: probe)
    )
    return probe
  }

  mutating func transition(
    id: UUID,
    from: PendingCredentialOperationPhase,
    to: PendingCredentialOperationPhase
  ) -> Bool {
    current?.transition(operationID: id, from: from, to: to) == true
  }

  mutating func terminate(id: UUID) -> Bool {
    guard let operation = takeToTerminal(id: id) else {
      return false
    }
    cleanup(operation)
    terminalCallbacks[id, default: 0] += 1
    return true
  }

  mutating func dismiss() -> Bool {
    guard let operation = takeCurrentToTerminal() else {
      return false
    }
    cleanup(operation)
    terminalCallbacks[operation.id, default: 0] += 1
    return true
  }

  private mutating func takeToTerminal(
    id: UUID
  ) -> PendingCredentialOperation<FakePayload, FakeResources>? {
    guard var operation = current,
          operation.terminate(operationID: id)
    else {
      return nil
    }
    current = nil
    return operation
  }

  private mutating func takeCurrentToTerminal() -> PendingCredentialOperation<FakePayload, FakeResources>? {
    guard let id = current?.id else {
      return nil
    }
    return takeToTerminal(id: id)
  }

  private func cleanup(
    _ operation: PendingCredentialOperation<FakePayload, FakeResources>
  ) {
    let probe = operation.resources.probe
    probe.delayedStartCancellations += 1
    probe.previewTaskCancellations += 1
    probe.previewSessionCancellations += 1
    probe.alertDismissals += 1
    probe.authenticationInvalidations += 1
    probe.identityStoreTaskCancellations += 1
  }
}

@main
struct PasskeyPendingOperationHarness {
  private static let registrationID = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
  private static let assertionID = UUID(uuidString: "00000000-0000-0000-0000-000000000002")!
  private static let successorID = UUID(uuidString: "00000000-0000-0000-0000-000000000003")!

  static func main() throws {
    guard CommandLine.arguments.count == 3 else {
      throw HarnessError("usage: harness <controller.swift> <app.plugin.js>")
    }

    try testRegistrationHappyPath()
    try testAssertionHappyPaths()
    try testIllegalTransitionsAndStaleIDs()
    try testReplacementAtEveryPhase()
    try testTerminalAndCleanupIdempotence()
    try testRegistrationFailureMatrix()
    try testAssertionFailureMatrix()
    try testLifecycleCleanup()
    try assertControllerLifecycleInvariants(sourcePath: CommandLine.arguments[1])
    try assertExtensionSourceRegistration(pluginPath: CommandLine.arguments[2])

    print("Validated pending passkey operation transitions, replacement barriers, and cleanup ownership.")
  }

  private static func testRegistrationHappyPath() throws {
    var driver = HarnessDriver()
    driver.begin(
      id: registrationID,
      kind: .registration,
      payload: .registration("request-and-identity")
    )
    try expectPhase(driver, .waiting, "registration waits before viewDidAppear")
    try require(
      driver.transition(id: registrationID, from: .waiting, to: .authenticating),
      "registration did not start authentication after viewDidAppear"
    )
    try require(
      driver.transition(id: registrationID, from: .authenticating, to: .completing),
      "registration did not enter Apple completion"
    )
    try require(driver.terminate(id: registrationID), "registration did not terminate")
    try require(driver.current?.id == nil, "registration remained current after completion")
  }

  private static func testAssertionHappyPaths() throws {
    var noPreview = HarnessDriver()
    noPreview.begin(
      id: assertionID,
      kind: .assertion(requiresPreview: false),
      payload: .assertion("credential-hash-rp")
    )
    try require(
      noPreview.transition(id: assertionID, from: .waiting, to: .authenticating),
      ".never assertion did not skip preview"
    )
    try require(
      noPreview.transition(id: assertionID, from: .authenticating, to: .completing),
      ".never assertion did not enter completion"
    )
    try require(noPreview.terminate(id: assertionID), ".never assertion did not terminate")

    var requiredPreview = HarnessDriver()
    requiredPreview.begin(
      id: assertionID,
      kind: .assertion(requiresPreview: true),
      payload: .assertion("immutable-preview-facts")
    )
    let transitions: [(PendingCredentialOperationPhase, PendingCredentialOperationPhase)] = [
      (PendingCredentialOperationPhase.waiting, .loadingPreview),
      (.loadingPreview, .presentingPreview),
      (.presentingPreview, .authenticating),
      (.authenticating, .completing),
    ]
    for (from, to) in transitions {
      try require(
        requiredPreview.transition(id: assertionID, from: from, to: to),
        "required-preview assertion rejected \(from) -> \(to)"
      )
    }
    try require(
      requiredPreview.terminate(id: assertionID),
      "required-preview assertion did not terminate"
    )
  }

  private static func testIllegalTransitionsAndStaleIDs() throws {
    var driver = HarnessDriver()
    let oldProbe = driver.begin(
      id: assertionID,
      kind: .assertion(requiresPreview: true),
      payload: .assertion("assertion")
    )
    try require(
      !driver.transition(id: assertionID, from: .waiting, to: .completing),
      "assertion allowed waiting -> completing"
    )
    try require(
      !driver.transition(id: assertionID, from: .waiting, to: .authenticating),
      "required preview was bypassed"
    )
    try require(
      !driver.transition(id: successorID, from: .waiting, to: .loadingPreview),
      "stale operation ID changed the current operation"
    )
    try expectPhase(driver, .waiting, "illegal transition changed phase")

    driver.begin(
      id: successorID,
      kind: .registration,
      payload: .registration("successor")
    )
    try requireCleanupOnce(oldProbe, "superseded assertion")
    try require(
      !driver.transition(id: assertionID, from: .waiting, to: .loadingPreview),
      "superseded callback changed its successor"
    )
    try require(!driver.terminate(id: assertionID), "superseded callback terminated its successor")
    try require(
      driver.current?.id == successorID && driver.current?.phase == .waiting,
      "stale callback mutated successor state"
    )
  }

  private static func testReplacementAtEveryPhase() throws {
    let phases: [PendingCredentialOperationPhase] = [
      .waiting,
      .loadingPreview,
      .presentingPreview,
      .authenticating,
      .completing,
    ]

    for phase in phases {
      var driver = HarnessDriver()
      let oldProbe = driver.begin(
        id: assertionID,
        kind: .assertion(requiresPreview: true),
        payload: .assertion("old")
      )
      try advanceRequiredAssertion(&driver, id: assertionID, to: phase)
      driver.begin(
        id: successorID,
        kind: .registration,
        payload: .registration("new")
      )
      try requireCleanupOnce(oldProbe, "replacement at \(phase)")
      try require(
        driver.current?.id == successorID && driver.current?.phase == .waiting,
        "replacement at \(phase) did not install a fresh waiting operation"
      )
      try require(
        !driver.terminate(id: assertionID),
        "old callback at \(phase) terminated the replacement"
      )
    }
  }

  private static func testTerminalAndCleanupIdempotence() throws {
    var driver = HarnessDriver()
    let probe = driver.begin(
      id: registrationID,
      kind: .registration,
      payload: .registration("registration")
    )
    try require(driver.terminate(id: registrationID), "first terminal callback was rejected")
    try require(!driver.terminate(id: registrationID), "second terminal callback was accepted")
    try require(!driver.dismiss(), "dismissal cleaned an already-terminal operation")
    try require(driver.terminalCallbacks[registrationID] == 1, "terminal callback ran more than once")
    try requireCleanupOnce(probe, "terminal cleanup")
  }

  private static func testRegistrationFailureMatrix() throws {
    for scenario in [
      "LA unavailable",
      "user cancellation",
    ] {
      var driver = HarnessDriver()
      driver.begin(
        id: registrationID,
        kind: .registration,
        payload: .registration(scenario)
      )
      try require(
        driver.transition(id: registrationID, from: .waiting, to: .authenticating),
        "\(scenario): registration did not authenticate"
      )
      try require(driver.terminate(id: registrationID), "\(scenario): registration did not cancel")
    }

    for scenario in [
      "missing credential store/root",
      "credential save failure",
      "identity-store refresh failure",
      "success",
    ] {
      var driver = HarnessDriver()
      driver.begin(
        id: registrationID,
        kind: .registration,
        payload: .registration(scenario)
      )
      try require(
        driver.transition(id: registrationID, from: .waiting, to: .authenticating),
        "\(scenario): registration did not authenticate"
      )
      try require(
        driver.transition(id: registrationID, from: .authenticating, to: .completing),
        "\(scenario): registration did not enter completing"
      )
      // A saved credential remains usable even if the identity index refresh fails;
      // the controller logs that refresh failure and still submits the saved credential.
      try require(driver.terminate(id: registrationID), "\(scenario): registration did not terminate")
    }

    var beforeAppearance = HarnessDriver()
    beforeAppearance.begin(
      id: registrationID,
      kind: .registration,
      payload: .registration("before appearance")
    )
    try expectPhase(beforeAppearance, .waiting, "request before viewDidAppear started early")
    try require(
      beforeAppearance.transition(id: registrationID, from: .waiting, to: .authenticating),
      "request before viewDidAppear did not start when visible"
    )

    var afterAppearance = HarnessDriver()
    afterAppearance.begin(
      id: registrationID,
      kind: .registration,
      payload: .registration("after appearance")
    )
    try require(
      afterAppearance.transition(id: registrationID, from: .waiting, to: .authenticating),
      "request after viewDidAppear did not use the waiting transition"
    )

    var delayedStart = HarnessDriver()
    let delayedProbe = delayedStart.begin(
      id: registrationID,
      kind: .registration,
      payload: .registration("delayed old request")
    )
    delayedStart.begin(
      id: successorID,
      kind: .registration,
      payload: .registration("delayed replacement")
    )
    try requireCleanupOnce(delayedProbe, "delayed-start replacement")
  }

  private static func testAssertionFailureMatrix() throws {
    for scenario in ["preview unavailable", "preview malformed", "preview redirected"] {
      var driver = HarnessDriver()
      driver.begin(
        id: assertionID,
        kind: .assertion(requiresPreview: true),
        payload: .assertion(scenario)
      )
      try require(
        driver.transition(id: assertionID, from: .waiting, to: .loadingPreview),
        "\(scenario): preview did not start"
      )
      try require(driver.terminate(id: assertionID), "\(scenario): assertion did not fail closed")
    }

    var previewCancellation = HarnessDriver()
    previewCancellation.begin(
      id: assertionID,
      kind: .assertion(requiresPreview: true),
      payload: .assertion("preview cancellation")
    )
    try advanceRequiredAssertion(&previewCancellation, id: assertionID, to: .presentingPreview)
    try require(
      previewCancellation.terminate(id: assertionID),
      "preview cancellation did not terminate"
    )

    for scenario in ["LA unavailable", "LA cancellation", "signing failure", "success"] {
      var driver = HarnessDriver()
      driver.begin(
        id: assertionID,
        kind: .assertion(requiresPreview: false),
        payload: .assertion(scenario)
      )
      try require(
        driver.transition(id: assertionID, from: .waiting, to: .authenticating),
        "\(scenario): assertion did not authenticate"
      )
      if scenario == "signing failure" || scenario == "success" {
        try require(
          driver.transition(id: assertionID, from: .authenticating, to: .completing),
          "\(scenario): assertion did not enter completing"
        )
      }
      try require(driver.terminate(id: assertionID), "\(scenario): assertion did not terminate")
    }
  }

  private static func testLifecycleCleanup() throws {
    var driver = HarnessDriver()
    let probe = driver.begin(
      id: assertionID,
      kind: .assertion(requiresPreview: true),
      payload: .assertion("lifecycle")
    )
    try advanceRequiredAssertion(&driver, id: assertionID, to: .presentingPreview)
    try require(driver.dismiss(), "dismissal did not terminate current operation")
    try requireCleanupOnce(probe, "dismiss/deinit cleanup")
    try require(!driver.dismiss(), "lifecycle cleanup was not idempotent")
  }

  private static func advanceRequiredAssertion(
    _ driver: inout HarnessDriver,
    id: UUID,
    to target: PendingCredentialOperationPhase
  ) throws {
    let path: [PendingCredentialOperationPhase] = [
      .waiting,
      .loadingPreview,
      .presentingPreview,
      .authenticating,
      .completing,
    ]
    guard let targetIndex = path.firstIndex(of: target) else {
      throw HarnessError("unsupported target phase \(target)")
    }
    if targetIndex == 0 {
      return
    }
    for index in 1...targetIndex {
      try require(
        driver.transition(id: id, from: path[index - 1], to: path[index]),
        "could not advance required assertion to \(target)"
      )
    }
  }

  private static func expectPhase(
    _ driver: HarnessDriver,
    _ phase: PendingCredentialOperationPhase,
    _ message: String
  ) throws {
    try require(driver.current?.phase == phase, message)
  }

  private static func requireCleanupOnce(_ probe: CleanupProbe, _ name: String) throws {
    for (resource, count) in [
      ("delayed start", probe.delayedStartCancellations),
      ("preview task", probe.previewTaskCancellations),
      ("preview session", probe.previewSessionCancellations),
      ("preview alert", probe.alertDismissals),
      ("authentication context", probe.authenticationInvalidations),
      ("identity-store task", probe.identityStoreTaskCancellations),
    ] {
      try require(count == 1, "\(name): \(resource) cleanup count was \(count)")
    }
  }

  private static func assertControllerLifecycleInvariants(sourcePath: String) throws {
    let source = try String(contentsOfFile: sourcePath, encoding: .utf8)
    for fragment in [
      "private struct RegistrationRequestSnapshot",
      "private struct AssertionRequestSnapshot",
      "private var pendingOperation",
      "kind: payload.kind",
      "private func updateOperationResources",
      "guard pendingOperation?.id == operationID",
      "operation.terminate(operationID: operationID)",
      "override func viewDidDisappear",
      "presentedViewController === alert",
      "deinit {",
      "scheduleStartForCurrentOperation()",
      "phase: .loadingPreview",
      "phase: .presentingPreview",
      "phase: .authenticating",
      "phase: .completing",
      "RejectingRedirectSessionDelegate()",
      "completionHandler(nil)",
      "store?.signingCredential(id: request.credential.credentialIdData)",
      "signingCredential.transactionPreviewPolicy == request.credential.transactionPreviewPolicy",
      "signingCredential.sign(authenticatorData + request.clientDataHash)",
      "replaceIdentityStore after registration failed; continuing with saved credential",
      "Self.cleanupResources(operation.resources)",
    ] where !source.contains(fragment) {
      throw HarnessError("controller is missing lifecycle invariant: \(fragment)")
    }

    for fragment in [
      "pendingRegistrationRequest",
      "pendingRegistrationIdentity",
      "assertionPhase",
      "isCompletingRegistration",
      "pendingAssertionCredential",
      "pendingAssertionClientDataHash",
      "pendingAssertionRelyingPartyIdentifier",
      "pendingRegistrationPrfInput",
      "pendingAssertionPrfInput",
      "isCompletingAssertion",
      "authContext",
      "URLSession.shared",
    ] where source.contains(fragment) {
      throw HarnessError("controller retained split or redirecting state: \(fragment)")
    }

    try require(
      occurrences(of: "extensionContext.cancelRequest(", in: source) == 1,
      "extension cancellation is not centralized"
    )
    try require(
      occurrences(of: "extensionContext.completeRegistrationRequest(", in: source) == 1,
      "registration has more than one Apple completion owner"
    )
    try require(
      occurrences(of: "extensionContext.completeAssertionRequest(", in: source) == 1,
      "assertion has more than one Apple completion owner"
    )
    try require(
      occurrences(of: "supersedeCurrentOperation()", in: source) >= 5,
      "not every incoming request supersedes current work"
    )
    try require(
      occurrences(of: "private var pendingOperation", in: source) == 1,
      "controller has more than one pending-operation authority"
    )
    try require(
      occurrences(of: "Self.cleanupResources(operation.resources)", in: source) == 1,
      "terminal transition and resource cleanup do not have one owner"
    )
    for cleanup in [
      "resources.delayedStart?.cancel()",
      "resources.transactionPreviewTask?.cancel()",
      "resources.transactionPreviewSession?.invalidateAndCancel()",
      "resources.transactionPreviewAlert?.dismiss(animated: false)",
      "resources.authenticationContext?.invalidate()",
      "resources.identityStoreTask?.cancel()",
    ] {
      try require(
        occurrences(of: cleanup, in: source) == 1,
        "resource cleanup is not centralized: \(cleanup)"
      )
    }
  }

  /// The Expo config plugin copies IOS_EXTENSION_FILES into the app and adds them
  /// to the extension target, so each source must be listed there exactly once.
  private static func assertExtensionSourceRegistration(pluginPath: String) throws {
    let plugin = try String(contentsOfFile: pluginPath, encoding: .utf8)
    for file in ["PendingCredentialOperation.swift", "TransactionPreviewPolicy.swift"] {
      try require(
        occurrences(of: "\"\(file)\",", in: plugin) == 1,
        "\(file) is not listed exactly once in the config plugin's IOS_EXTENSION_FILES"
      )
    }
  }

  private static func occurrences(of needle: String, in haystack: String) -> Int {
    haystack.components(separatedBy: needle).count - 1
  }

  private static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    guard condition() else {
      throw HarnessError(message)
    }
  }
}

struct HarnessError: Error, CustomStringConvertible {
  let description: String

  init(_ description: String) {
    self.description = description
  }
}
