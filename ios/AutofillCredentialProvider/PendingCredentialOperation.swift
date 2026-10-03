import Foundation

enum PendingCredentialOperationKind: Equatable {
  case registration
  case assertion(requiresPreview: Bool)
}

enum PendingCredentialOperationPhase: Equatable {
  case waiting
  case loadingPreview
  case presentingPreview
  case authenticating
  case completing
  case terminal
}

struct PendingCredentialOperation<Payload, Resources> {
  let id: UUID
  let kind: PendingCredentialOperationKind
  let payload: Payload
  private(set) var phase: PendingCredentialOperationPhase
  var resources: Resources

  init(
    id: UUID = UUID(),
    kind: PendingCredentialOperationKind,
    payload: Payload,
    resources: Resources
  ) {
    self.id = id
    self.kind = kind
    self.payload = payload
    phase = .waiting
    self.resources = resources
  }

  mutating func transition(
    operationID: UUID,
    from expectedPhase: PendingCredentialOperationPhase,
    to nextPhase: PendingCredentialOperationPhase
  ) -> Bool {
    guard id == operationID,
          phase == expectedPhase,
          Self.allows(kind: kind, from: expectedPhase, to: nextPhase)
    else {
      return false
    }

    phase = nextPhase
    return true
  }

  mutating func terminate(operationID: UUID) -> Bool {
    guard id == operationID, phase != .terminal else {
      return false
    }

    phase = .terminal
    return true
  }

  private static func allows(
    kind: PendingCredentialOperationKind,
    from currentPhase: PendingCredentialOperationPhase,
    to nextPhase: PendingCredentialOperationPhase
  ) -> Bool {
    switch (kind, currentPhase, nextPhase) {
    case (.registration, .waiting, .authenticating),
         (.assertion(requiresPreview: false), .waiting, .authenticating),
         (.assertion(requiresPreview: true), .waiting, .loadingPreview),
         (.assertion(requiresPreview: true), .loadingPreview, .presentingPreview),
         (.assertion(requiresPreview: _), .presentingPreview, .authenticating),
         (.registration, .authenticating, .completing),
         (.assertion(requiresPreview: _), .authenticating, .completing):
      return true
    default:
      return false
    }
  }
}
