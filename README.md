# iOS Sandbox Explorer

Inject a custom dylib into any iOS app IPA, **sign with an external tool**, install it, and get an interactive shell into that app’s sandbox over USB.

This is a **jailed / sideload** workflow: `libShell.dylib` is loaded via `LC_LOAD_DYLIB` (constructor inject). There is **no** Theos tweak, **no** Cydia Substrate, and **no** Ellekit in this repository.

Host Apple ID / GSA / anisette / Developer Portal signing is **not** part of this project. Sign with feather, [ipasigner](https://ipasigner.com), Sideloadly, zsign, or any other external signer.

## How it works

1. **Build** `libShell.dylib` — Objective-C TCP server with built-in sandbox-safe commands (no `popen`, no `exec`)
2. **Patch** an IPA with the F# tools — inject the dylib, ATS plist tweak, write sample entitlements, repack (**unsigned**)
3. **Sign** the patched IPA externally
4. **Install** (F# `install` via Netimobiledevice, or your signer’s install flow)
5. **Tunnel** USB → localhost and run shell commands / SCP / keychain dump

## Repository layout

```
src/                  — libShell Objective-C sources
include/              — public headers
Makefile              — builds libShell.dylib (macOS + Xcode iphoneos SDK)
tools-fs/             — F# host tooling (client, patch, devices, install, tunnel, full)
.github/workflows/
  build-dylib.yml     — macOS CI: build dylib on xcode-27 (iOS 27 SDK); Releases on v*.*.* tags
  build-fs-tools.yml  — Linux CI: restore/build F# tools + self-tests
```

There is **no** `tools/` Python tree, **no** `client.py` / `patcher.py`, and **no** `ios-patch/` legacy script directory.

## Prerequisites

### Build `libShell.dylib` (macOS)

- Xcode with an **iphoneos** SDK (CI uses the **iOS 27** SDK on the `xcode-27` runner)
- Deployment target stays **iOS 14.0** (`IPHONEOS_DEPLOYMENT_TARGET`)

```bash
xcode-select --install   # if needed
make                     # → libShell.dylib
```

Optional hard gate (matches CI):

```bash
REQUIRE_IOS_SDK_MAJOR=1 IPHONEOS_SDK_MIN_MAJOR=27 make
```

### Host tooling (any OS with .NET 8)

```bash
# .NET 8 SDK: https://dotnet.microsoft.com/download
dotnet build tools-fs/IosSandboxExplorer.Tools.sln -c Release
```

### Device USB (install / tunnel / list)

- A paired, trusted device
- **usbmuxd** (Linux/macOS) or Apple Mobile Device Support (Windows)
- F# device commands use [Netimobiledevice](https://github.com/artehe/Netimobiledevice) — no `pymobiledevice3` / no required `ideviceinstaller` / `iproxy` binaries

## Building / obtaining `libShell.dylib`

`libShell.dylib` is **not** committed to git.

| Source | Notes |
|--------|--------|
| `make` on macOS | Builds with current iphoneos SDK; min OS **14.0** |
| [GitHub Releases](https://github.com/gemsloot-iOS/iOS-sandbox-explorer/releases) | Published only when a semver tag `v*.*.*` is pushed to a commit **on `main`** |
| [Actions](https://github.com/gemsloot-iOS/iOS-sandbox-explorer/actions) artifact `libShell-dylib` | From workflow **Build libShell.dylib** (every push/PR; not a Release) |

CI facts (workflow `build-dylib.yml`):

- Runner: **`xcode-27`** (real iOS **27** SDK; fails if SDK major &lt; 27)
- Mach-O check: `minos 14.0` and `sdk 27.x`
- Releases: tag push `v*.*.*` only — CI never creates tags

## F# host tools

Project: `tools-fs/IosSandboxExplorer.Tools`

```bash
# Shell client (TCP to libShell on device via tunnel)
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- "ls"
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- client "pwd" --host localhost --port 8080
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- "scp -r Documents host:./downloads"

# Patch IPA (unsigned output)
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- patch --ipa MyApp.ipa --dylib libShell.dylib
# → MyApp_patched.ipa

# Device helpers (Netimobiledevice)
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- devices
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- install --ipa MyApp_signed.ipa [--udid UDID]
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- tunnel [--local-port 8080] [--remote-port 8080] [--udid UDID]

# Patch then optionally install (still unsigned unless you signed first)
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- full --ipa MyApp.ipa --dylib libShell.dylib [--install] [--udid UDID]

# Offline self-tests (also run in CI)
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- --self-test
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- --self-test-patcher
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- --self-test-devices
```

`--use-lief` is accepted on `patch` / `full` for old-CLI compatibility; F# inject already reclaims `LC_CODE_SIGNATURE` space when needed (no Python `lief`).

## Sign externally, then install

```bash
# After patch — sign with feather / ipasigner / Sideloadly / zsign / etc.
# Then:
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- install --ipa MyApp_signed.ipa
```

## Connect and use

1. Launch the patched app on the device (dylib starts a TCP server on **port 8080**, loopback on device).
2. Start a USB tunnel:

```bash
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- tunnel --local-port 8080 --remote-port 8080
# foreground; Ctrl+C to stop
```

3. Run commands from the host (examples above).

## Available commands (dylib)

Implemented in-process via Foundation/POSIX — **no `popen()`, no `exec()`**. Full list: run `help` on the device shell.

Highlights:

| Area | Examples |
|------|----------|
| Navigation | `ls`, `cd`, `pwd`, `tree` |
| Files | `cat`, `head`, `tail`, `hexdump`, `cp`, `mv`, `rm`, `mkdir`, `stat`, `find`, `grep`, … |
| System | `id`, `uname`, `env`, `bundle`, `sandbox`, `sysinfo`, `memory`, … |
| Keychain | `keychain dump`, `keychain dump --filter …`, `keychain groups` |
| Transfer | `scp -r <src> host:<dst>`, `download` |
| Meta | `help`, `version` |

Keychain access is limited to what this app’s entitlements allow. There is **no** `--jailbreak` patcher flag.

## Out of scope

| Topic | Status |
|-------|--------|
| Host Apple ID / anisette / portal signing | Removed — use external signers |
| Python host tools | Removed — use `tools-fs` |
| Theos jailbreak tweak path | Not used / not shipped |
| Cydia Substrate / Ellekit | Not used — product path is constructor `LC_LOAD_DYLIB` inject only |
| Auto-tagging on every `main` push | No — Releases only on `v*.*.*` tags |

## Troubleshooting

### `Connection refused` on port 8080

- Patched app must be running
- Tunnel must be up (`tunnel` or equivalent)
- Relaunch the app after install

### Install / device list fails

- Device unlocked, trusted, and paired
- usbmuxd / Apple Mobile Device Support running
- IPA must be **signed** for the target device before `install` succeeds

### App rejected (`ApplicationVerificationFailed`)

- Re-sign with a valid external cert / profile matching the device UDID

### `make` / iphoneos SDK errors

- Need macOS + Xcode with an iphoneos SDK
- CI requires SDK major ≥ 27; locally, older SDKs may still build but will warn

## Security notes

- For testing and research only
- Injected code runs inside the host app’s sandbox
- Shell TCP is bound to loopback on device; reach it over USB tunnel, not the LAN
