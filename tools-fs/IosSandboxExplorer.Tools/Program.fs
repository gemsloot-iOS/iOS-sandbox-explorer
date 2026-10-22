// CLI — F# host tools (client + patch + apple signing).
// Python counterparts kept until Phase 10 cutover.

module Program

open System
open System.IO
open IosSandboxExplorer

let private usage () =
    printfn "IosSandboxExplorer.Tools — F# host tooling"
    printfn ""
    printfn "Client:"
    printfn "  IosSandboxExplorer.Tools <command> [--host HOST] [--port PORT]"
    printfn "  IosSandboxExplorer.Tools client <command> [--host HOST] [--port PORT]"
    printfn "  IosSandboxExplorer.Tools --self-test"
    printfn ""
    printfn "Patch (no Apple ID):"
    printfn "  IosSandboxExplorer.Tools patch --ipa FILE --dylib FILE [-o OUT.ipa]"
    printfn "  IosSandboxExplorer.Tools --self-test-patcher"
    printfn ""
    printfn "Apple ID / signing (Phase 9b — live GSA/SRP in F#):"
    printfn "  IosSandboxExplorer.Tools apple check [--anisette-url URL]"
    printfn "  IosSandboxExplorer.Tools apple sign --ipa FILE --skip-sign"
    printfn "  IosSandboxExplorer.Tools apple sign --ipa FILE [--output OUT] [--udid UDID] [--bundle-id ID] [--anisette-url URL]"
    printfn "  IosSandboxExplorer.Tools --self-test-apple"
    printfn ""
    printfn "TLS: certificate validation ON by default. Override only via IOS_SANDBOX_TLS_INSECURE=1."
    printfn "Anisette: HTTP server or macOS anisette_helper (no embedded Linux Unicorn ADI)."

let private parseClientFlags (argv: string[]) (start: int) =
    let mutable host = "localhost"
    let mutable port = 8080
    let mutable command: string option = None
    let mutable i = start
    let mutable err: string option = None
    while i < argv.Length && err.IsNone do
        match argv[i] with
        | "--host" when i + 1 < argv.Length ->
            host <- argv[i + 1]
            i <- i + 2
        | "--port" when i + 1 < argv.Length ->
            match Int32.TryParse(argv[i + 1]) with
            | true, p ->
                port <- p
                i <- i + 2
            | _ -> err <- Some $"Invalid --port: {argv[i + 1]}"
        | flag when flag.StartsWith("-") -> err <- Some $"Unknown option: {flag}"
        | cmd ->
            match command with
            | Some _ -> err <- Some "Only one shell command is allowed"
            | None ->
                command <- Some cmd
                i <- i + 1
    match err, command with
    | Some e, _ -> Error e
    | None, None -> Error "missing shell command"
    | None, Some c -> Ok(c, host, port)

let private parsePatchFlags (argv: string[]) (start: int) =
    let mutable ipa: string option = None
    let mutable dylib: string option = None
    let mutable output: string option = None
    let mutable i = start
    let mutable err: string option = None
    while i < argv.Length && err.IsNone do
        match argv[i] with
        | "--ipa" when i + 1 < argv.Length ->
            ipa <- Some argv[i + 1]
            i <- i + 2
        | "--dylib" when i + 1 < argv.Length ->
            dylib <- Some argv[i + 1]
            i <- i + 2
        | "--output" | "-o" when i + 1 < argv.Length ->
            output <- Some argv[i + 1]
            i <- i + 2
        | flag when flag.StartsWith("-") -> err <- Some $"Unknown patch option: {flag}"
        | other -> err <- Some $"Unexpected argument: {other}"
    match err with
    | Some e -> Error e
    | None ->
        match ipa, dylib with
        | Some i, Some d ->
            let o =
                match output with
                | Some x -> x
                | None ->
                    let dir = Path.GetDirectoryName(i)
                    let name = Path.GetFileNameWithoutExtension(i) + "_patched.ipa"
                    if String.IsNullOrEmpty(dir) then name else Path.Combine(dir, name)
            Ok(i, d, o)
        | None, _ -> Error "patch requires --ipa"
        | _, None -> Error "patch requires --dylib"

type private AppleSignArgs =
    { Ipa: string
      Skip: bool
      Url: string
      Output: string option
      Udid: string option
      BundleId: string option }

let private parseAppleArgs (argv: string[]) =
    if argv.Length < 2 then Error "apple requires a subcommand: check | sign"
    else
        match argv[1] with
        | "check" ->
            let mutable url = Anisette.defaultAnisetteUrl
            let mutable i = 2
            let mutable err: string option = None
            while i < argv.Length && err.IsNone do
                match argv[i] with
                | "--anisette-url" when i + 1 < argv.Length ->
                    url <- argv[i + 1]
                    i <- i + 2
                | flag -> err <- Some $"Unknown check option: {flag}"
            match err with
            | Some e -> Error e
            | None -> Ok(Choice1Of2 url)
        | "sign" ->
            let mutable ipa: string option = None
            let mutable skip = false
            let mutable url = Anisette.defaultAnisetteUrl
            let mutable output: string option = None
            let mutable udid: string option = None
            let mutable bundleId: string option = None
            let mutable i = 2
            let mutable err: string option = None
            while i < argv.Length && err.IsNone do
                match argv[i] with
                | "--ipa" when i + 1 < argv.Length ->
                    ipa <- Some argv[i + 1]
                    i <- i + 2
                | "--skip-sign" ->
                    skip <- true
                    i <- i + 1
                | "--anisette-url" when i + 1 < argv.Length ->
                    url <- argv[i + 1]
                    i <- i + 2
                | "--output" | "-o" when i + 1 < argv.Length ->
                    output <- Some argv[i + 1]
                    i <- i + 2
                | "--udid" when i + 1 < argv.Length ->
                    udid <- Some argv[i + 1]
                    i <- i + 2
                | "--bundle-id" when i + 1 < argv.Length ->
                    bundleId <- Some argv[i + 1]
                    i <- i + 2
                | flag when flag.StartsWith("-") -> err <- Some $"Unknown sign option: {flag}"
                | other -> err <- Some $"Unexpected: {other}"
            match err, ipa with
            | Some e, _ -> Error e
            | None, None -> Error "apple sign requires --ipa"
            | None, Some path ->
                Ok(
                    Choice2Of2
                        { Ipa = path
                          Skip = skip
                          Url = url
                          Output = output
                          Udid = udid
                          BundleId = bundleId }
                )
        | other -> Error $"Unknown apple subcommand: {other}"

let private runApple (cmd: Choice<string, AppleSignArgs>) =
    match cmd with
    | Choice1Of2 url -> AppleSign.checkAnisette url
    | Choice2Of2 args when args.Skip ->
        match AppleSign.signIpaSkipSign args.Ipa with
        | Ok _ -> 0
        | Error e ->
            eprintfn "[!] %s" e
            1
    | Choice2Of2 args ->
        match AppleSign.signIpaLive args.Ipa args.Output args.Udid args.BundleId args.Url with
        | Ok path ->
            printfn "[+] Done: %s" path
            0
        | Error e ->
            eprintfn "[!] %s" e
            1

let private selfTestApple () =
    let srp = AppleSrp.selfTest ()
    if srp <> 0 then srp
    else
        let a = Anisette.selfTest ()
        if a <> 0 then a
        else
            let c = AppleCrypto.selfTest ()
            if c <> 0 then c
            else
                let tmp =
                    Path.Combine(
                        Path.GetTempPath(),
                        "apple-skip-" + Guid.NewGuid().ToString("N") + ".ipa"
                    )
                File.WriteAllBytes(tmp, [| 0x50uy; 0x4Buy |])
                try
                    match AppleSign.signIpaSkipSign tmp with
                    | Ok p when p = tmp ->
                        // Live path requires interactive credentials — do not call it in CI.
                        printfn
                            "self-test-apple OK: SRP vectors + anisette + crypto + skip-sign (live path is interactive)"
                        0
                    | Ok _ ->
                        eprintfn "self-test-apple FAIL: skip-sign path mismatch"
                        1
                    | Error e ->
                        eprintfn "self-test-apple FAIL: %s" e
                        1
                finally
                    try File.Delete(tmp) with _ -> ()

[<EntryPoint>]
let main argv =
    if argv.Length = 0 then
        usage ()
        1
    else
        match argv[0] with
        | "--help" | "-h" ->
            usage ()
            0
        | "--self-test" -> Client.selfTest ()
        | "--self-test-patcher" -> Patcher.selfTest ()
        | "--self-test-srp" -> AppleSrp.selfTest ()
        | "--self-test-apple" -> selfTestApple ()
        | "patch" ->
            match parsePatchFlags argv 1 with
            | Error e ->
                eprintfn "Error: %s" e
                usage ()
                1
            | Ok(ipa, dylib, output) ->
                match Patcher.patchIpa ipa dylib output with
                | Ok r ->
                    printfn ""
                    printfn "[+] PATCHED IPA READY (unsigned)"
                    printfn "    Output: %s" r.OutputPath
                    printfn "    Sign with: IosSandboxExplorer.Tools apple sign --ipa %s" r.OutputPath
                    printfn "            or: IosSandboxExplorer.Tools apple sign --ipa %s --skip-sign" r.OutputPath
                    0
                | Error e ->
                    eprintfn "[!] %s" e
                    1
        | "apple" ->
            match parseAppleArgs argv with
            | Error e ->
                eprintfn "Error: %s" e
                usage ()
                1
            | Ok token -> runApple token
        | "client" ->
            match parseClientFlags argv 1 with
            | Error e ->
                eprintfn "Error: %s" e
                usage ()
                1
            | Ok(cmd, host, port) -> Client.runCommand host port cmd
        | _ ->
            match parseClientFlags argv 0 with
            | Error e ->
                eprintfn "Error: %s" e
                usage ()
                1
            | Ok(cmd, host, port) -> Client.runCommand host port cmd
