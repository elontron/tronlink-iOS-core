# AGENTS.md

## Project overview

**tronlink-iOS-core** is a CocoaPods-distributed iOS SDK (`TLCore`) for the TronLink Wallet. It provides wallet creation, address derivation, transaction/message signing, gRPC TRON protocol bindings, and optional anonymized metrics.

The repo is **not** a standalone server or web app. Development centers on:

| Path | Purpose |
|------|---------|
| `tronlink-iOS-core/` | Library source (Swift + generated ObjC gRPC/Protobuf) |
| `Example/` | Sample iOS app + XCTest suite |
| `tronlink-iOS-core.podspec` | CocoaPods spec |

## Cursor Cloud specific instructions

### Platform constraint (important)

This is an **iOS-only** project. **Building, running the Example app, and executing XCTest require macOS with Xcode and an iOS Simulator or device.** Linux Cloud Agent VMs cannot compile or run iOS targets.

On Linux, agents can install Ruby/CocoaPods and validate the podspec/Podfile, but `pod install` typically **fails** while installing the transitive `TrezorCrypto` pod (its `prepare_command` uses `git submodule` and macOS `sed -i ''` syntax). Full dependency resolution and builds should be done on macOS.

### One-time system packages (Linux VM bootstrap)

If Ruby/CocoaPods are missing:

```bash
sudo apt-get update
sudo apt-get install -y ruby-full ruby-dev build-essential git libffi-dev rsync
sudo gem install cocoapods -N
```

### Dependency install (macOS — full workflow)

```bash
cd Example
pod install
open tronlink-iOS-core.xcworkspace   # generated after pod install
```

In Xcode, run scheme **`tronlink-iOS-core_Example`** (app) or **`tronlink-iOS-core_Tests`** (tests).

### Linux-side validation (no build)

Useful checks when Xcode is unavailable:

```bash
# Validate podspec parses and lists correct dependencies
pod ipc spec tronlink-iOS-core.podspec

# Validate Example Podfile structure
cd Example && pod ipc podfile Podfile
```

### Tests

XCTest lives in `Example/Tests/Tests.swift`. Key tests:

| Test | External network |
|------|------------------|
| `testCreateWallet` | No |
| `testSignMessage` | No |
| `testExportPrivateKey` | No |
| `testExportMnemonic` | No |
| `testSignTransaction` | Yes — TRON gRPC full node at `18.206.50.220:50051` |

Run tests via Xcode scheme **`tronlink-iOS-core_Tests`** on macOS only.

### Lint / CI

No SwiftLint, RuboCop, Makefile, or GitHub Actions workflows are present in this repo. There is no automated lint step beyond Xcode build warnings.

### Gotchas

- First `pod install` clones the full CocoaPods Specs git repo (~800k files) and can take several minutes.
- `Pods/`, `Podfile.lock`, and `*.xcworkspace` are gitignored; regenerate with `pod install`.
- `FBSnapshotTestCase` is listed in the Example Podfile but not used in tests.
- Metrics upload is delegated to host apps via `TRXMetricsDataSource`; no metrics server exists in this repo.
