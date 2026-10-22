# iOS Sandbox Explorer

Inject a custom DYLIB into any iOS app, sign the IPA with an **external** signer (feather, ipasigner.com, Sideloadly, zsign, etc.), install it, and get interactive shell access to the app's sandbox over USB — on any device, jailbroken or not.

Host Apple ID / GSA / anisette signing is **not** part of this project.

## How It Works

1. **Build** `libShell.dylib` — an Objective-C TCP server with built-in sandbox-safe commands (no `popen`, no `exec`)
2. **Patch** any IPA — inject the DYLIB, add network entitlements, update `Info.plist`
3. **Sign** the patched IPA with an external tool of your choice
4. **Install** to device (e.g. `ideviceinstaller` or your signer’s install flow)
5. **Connect** via USB tunnel → run commands, dump keychain, download files from the app's sandbox

## Architecture

```
src/
  main.m              — DYLIB entry point, starts TCP server
  ShellServer.m       — TCP server (port 8080)
  ShellCommands.m     — Built-in commands (sandbox-safe, no popen)
include/
  ShellServer.h
  ShellCommands.h
tools/
  patcher.py          — Python IPA patcher + device helpers (F# covers inject; see plan parity matrix)
tools-fs/             — F# host tooling (TCP client + IPA patch/inject)
Makefile              — Builds libShell.dylib (macOS / Xcode iphoneos SDK)
```

## Prerequisites

### macOS

```bash
# Python & dependencies (optional if using F# tools only)
python3 -m pip install -r tools/requirements.txt

# USB install / tunneling
brew install libimobiledevice ideviceinstaller

# DYLIB build (Xcode Command Line Tools)
xcode-select --install
```

### Linux (Ubuntu / Kali / Debian)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r tools/requirements.txt

sudo apt install libimobiledevice-utils ideviceinstaller
```

> **Note:** Always activate the venv before running Python tool commands:
> `source .venv/bin/activate`

## Building the DYLIB

`libShell.dylib` is **not** committed to this repository. Obtain it by building on macOS, or download a release/CI artifact.

### macOS (build from source)

```bash
make
```

Creates `libShell.dylib` in the project root.

### Other platforms (pre-built)

- **GitHub Releases** — download `libShell.dylib` from the latest [Release](https://github.com/gemsloot-iOS/iOS-sandbox-explorer/releases) (published when a semver tag such as `v0.0.1` is pushed).
- **CI artifacts** — download the `libShell-dylib` artifact from a green [Actions](https://github.com/gemsloot-iOS/iOS-sandbox-explorer/actions) run of **Build libShell.dylib**.

## Patching an IPA

```bash
# F# (preferred)
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- patch --ipa MyApp.ipa --dylib libShell.dylib

# Or Python
python3 tools/patcher.py patch --ipa MyApp.ipa --dylib libShell.dylib
# → MyApp_patched.ipa
```

Works on Windows, Linux, and macOS. No Xcode or `insert_dylib` required. Output is **unsigned** — sign with feather / ipasigner / Sideloadly / zsign (or similar) before install.

## Installing on Device

```bash
ideviceinstaller -u <device-udid> install MyApp_signed.ipa
```

## Connecting and Using

### 1. Launch the patched app on your device

### 2. Set up USB tunnel

```bash
iproxy 8080 8080
```

### 3. Run commands

```bash
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- "ls"
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- "pwd"
dotnet run --project tools-fs/IosSandboxExplorer.Tools -- "scp -r Documents host:./downloads"
```

## Available Commands

The DYLIB implements built-in commands — **no `popen()`, no `exec()`** (safe from iOS entitlement restrictions):

| Command | Description |
|---------|-------------|
| `ls [path]` | List directory |
| `pwd` | Current directory |
| `cd <path>` | Change directory |
| `id` | User and group IDs |
| `whoami` | Current username |
| `uname` | System information |
| `echo <text>` | Print text |
| `cat <file>` | Print file contents |
| `cp <src> <dst>` | Copy file/directory |
| `mv <src> <dst>` | Move file/directory |
| `rm <path>` | Remove file/directory |
| `mkdir <path>` | Create directory |
| `stat <path>` | File metadata |
| `find <path>` | Find files |
| `env` | Environment variables |
| `scp -r <src> host:<dst>` | Download to host (base64) |
| `keychain dump` | Dump all keychain items accessible to the app |
| `keychain dump --filter <str>` | Dump keychain items matching a string in any field |
| `keychain dump --filter self` | Dump keychain items matching the app's own bundle ID |
| `keychain dump --class <type>` | Filter by item class: `generic`, `internet`, `cert`, `key` |

## Troubleshooting

### `Connection refused` on port 8080
- Verify the patched app is running on device
- Check `iproxy 8080 8080` is running
- Try relaunching the app

### App rejected on install (`ApplicationVerificationFailed`)
- Re-sign with a valid external signer / fresh cert and matching device UDID

### `ideviceinstaller not found`
- macOS: `brew install ideviceinstaller`
- Linux: `apt install ideviceinstaller`
- Windows: [libimobiledevice-win32](https://github.com/libimobiledevice-win32/imobiledevice-net)

## Security Notes

- For testing and research purposes only
- Injected code runs entirely within the app's sandbox
- Network traffic is tunnelled over USB (never exposed to the network)
