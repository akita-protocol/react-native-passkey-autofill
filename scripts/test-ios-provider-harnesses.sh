#!/usr/bin/env bash
# Compiles and runs the host-side Swift harnesses for the iOS AutoFill provider:
# the closed transaction-preview policy (persistence, migration, alias
# quarantine) and the single pending-operation state machine, plus source-level
# invariants of CredentialProviderViewController.swift. Needs Xcode; no device.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROVIDER_DIR="${PROJECT_DIR}/ios/AutofillCredentialProvider"
HARNESS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/passkey-provider-harness.XXXXXX")"
trap 'rm -rf "${HARNESS_DIR}"' EXIT

xcrun swiftc \
  "${PROVIDER_DIR}/TransactionPreviewPolicy.swift" \
  "${SCRIPT_DIR}/passkey-preview-policy-harness.swift" \
  -o "${HARNESS_DIR}/passkey-preview-policy-harness"

"${HARNESS_DIR}/passkey-preview-policy-harness" \
  "${PROVIDER_DIR}/CredentialProviderViewController.swift"

xcrun swiftc \
  "${PROVIDER_DIR}/PendingCredentialOperation.swift" \
  "${SCRIPT_DIR}/passkey-pending-operation-harness.swift" \
  -o "${HARNESS_DIR}/passkey-pending-operation-harness"

"${HARNESS_DIR}/passkey-pending-operation-harness" \
  "${PROVIDER_DIR}/CredentialProviderViewController.swift" \
  "${PROJECT_DIR}/app.plugin.js"

xcrun swiftc \
  "${PROVIDER_DIR}/TransactionPreviewPolicy.swift" \
  "${SCRIPT_DIR}/passkey-credential-storage-harness.swift" \
  -o "${HARNESS_DIR}/passkey-credential-storage-harness"

"${HARNESS_DIR}/passkey-credential-storage-harness" \
  "${PROVIDER_DIR}/PasskeyCredentialStore.swift"
