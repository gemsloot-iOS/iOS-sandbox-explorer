// High-level Apple ID signing entrypoints (Phase 9).
// Live GSA/portal/zsign with credentials is NOT exercised in CI.
// Full interactive GSA SRP + Developer Portal parity remains available via
// Python tools/apple_account.py until a follow-up completes the live F# auth path.

module IosSandboxExplorer.AppleSign

open System
open System.IO

/// Mirror of apple_account.sign_ipa_with_apple_id(..., skip_sign=True).
let signIpaSkipSign (ipaPath: string) : Result<string, string> =
    if not (File.Exists(ipaPath)) then Error $"IPA not found: {ipaPath}"
    else
        printfn "[*] Signing skipped (--skip-sign)"
        printfn "[*] Unsigned IPA: %s" ipaPath
        printfn ""
        printfn "  To install unsigned IPA, use:"
        printfn "    • Sideloadly (handles signing automatically)"
        printfn "    • AltStore"
        printfn "    • Manual signing with zsign / p12 + mobileprovision"
        printfn "    • Python live Apple ID path: python3 tools/apple_account.py sign --ipa %s" ipaPath
        Ok ipaPath

/// Live Apple ID sign — not completed in this phase without offline-verifiable SRP/GSA.
/// Halts clearly rather than pretending to authenticate.
let signIpaLive (_ipaPath: string) (_outputPath: string option) (_udid: string option) (_bundleId: string option) (_anisetteUrl: string) : Result<string, string> =
    Error(
        "Live Apple ID GSA/SRP + Developer Portal signing is not fully ported to F# yet "
        + "(no offline-verifiable SRP session against Apple in CI; will not fake credentials).\n"
        + "Use: python3 tools/apple_account.py sign --ipa <file>\n"
        + "Or:  IosSandboxExplorer.Tools apple sign --ipa <file> --skip-sign\n"
        + "F# pieces ready: TLS (verify ON), Anisette HTTP/native helper hooks, password KDF + AES helpers."
    )

let checkAnisette (url: string) : int =
    use client = AppleTls.createClient ()
    printfn "[*] Checking anisette server: %s" url
    if Anisette.checkServer url client then
        printfn "[+] Server is UP"
        try
            use provider = new Anisette.HttpAnisetteProvider(url, client)
            let data = (provider :> Anisette.IAnisetteProvider).Fetch()
            let md = data |> Map.tryFind "X-Apple-I-MD" |> Option.defaultValue "N/A"
            let mdm = data |> Map.tryFind "X-Apple-I-MD-M" |> Option.defaultValue "N/A"
            let mdPreview = if md.Length > 20 then md.Substring(0, 20) + "..." else md
            let mdmPreview = if mdm.Length > 20 then mdm.Substring(0, 20) + "..." else mdm
            printfn "[+] X-Apple-I-MD:   %s" mdPreview
            printfn "[+] X-Apple-I-MD-M: %s" mdmPreview
            0
        with ex ->
            eprintfn "[!] Fetch failed after UP check: %s" ex.Message
            1
    else
        printfn "[!] Server is DOWN"
        printfn ""
        printfn "  Start an anisette HTTP server or use Python LinuxAnisetteProvider."
        printfn "  On macOS, build tools/anisette_helper via `make anisette_helper`."
        1
