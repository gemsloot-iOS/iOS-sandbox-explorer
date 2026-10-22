// CLI — F# host tools (client + patch). Python counterparts kept until cutover.
//
//   IosSandboxExplorer.Tools <shell-command> [--host HOST] [--port PORT]
//   IosSandboxExplorer.Tools client <shell-command> [--host HOST] [--port PORT]
//   IosSandboxExplorer.Tools patch --ipa FILE --dylib FILE [-o OUT]
//   IosSandboxExplorer.Tools --self-test
//   IosSandboxExplorer.Tools --self-test-patcher

module Program

open System
open System.IO
open IosSandboxExplorer

let private usage () =
    printfn "IosSandboxExplorer.Tools — F# host tooling (client + IPA patch)"
    printfn ""
    printfn "Client:"
    printfn "  IosSandboxExplorer.Tools <command> [--host HOST] [--port PORT]"
    printfn "  IosSandboxExplorer.Tools client <command> [--host HOST] [--port PORT]"
    printfn "  IosSandboxExplorer.Tools --self-test"
    printfn ""
    printfn "Patch (dylib inject only — sign externally):"
    printfn "  IosSandboxExplorer.Tools patch --ipa FILE --dylib FILE [-o OUT.ipa]"
    printfn "  IosSandboxExplorer.Tools --self-test-patcher"
    printfn ""
    printfn "IPA signing is out of scope (use feather / ipasigner / Sideloadly / zsign)."
    printfn "Python tools/patcher.py remains for install/devices/tunnel (no F# parity yet)."

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
                    printfn "    Sign externally (feather / ipasigner / Sideloadly / zsign), then install."
                    0
                | Error e ->
                    eprintfn "[!] %s" e
                    1
        | "client" ->
            match parseClientFlags argv 1 with
            | Error e ->
                eprintfn "Error: %s" e
                usage ()
                1
            | Ok(cmd, host, port) -> Client.runCommand host port cmd
        | _ ->
            // Backward-compatible: first token is the shell command (Phase 7 CLI).
            match parseClientFlags argv 0 with
            | Error e ->
                eprintfn "Error: %s" e
                usage ()
                1
            | Ok(cmd, host, port) -> Client.runCommand host port cmd
