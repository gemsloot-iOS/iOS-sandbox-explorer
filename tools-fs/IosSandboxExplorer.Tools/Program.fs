// CLI entry — F# counterpart to client.py (Python kept until cutover).
// Usage:
//   dotnet run --project tools-fs/IosSandboxExplorer.Tools -- "ls"
//   dotnet run --project tools-fs/IosSandboxExplorer.Tools -- "pwd" --host localhost --port 8080
//   dotnet run --project tools-fs/IosSandboxExplorer.Tools -- --self-test

module Program

open System
open IosSandboxExplorer.Client

type private Args =
    { Command: string option
      Host: string
      Port: int
      SelfTest: bool }

let private usage () =
    printfn "IosSandboxExplorer.Tools — iOS shell TCP client (F# port of client.py)"
    printfn ""
    printfn "Usage:"
    printfn "  IosSandboxExplorer.Tools <command> [--host HOST] [--port PORT]"
    printfn "  IosSandboxExplorer.Tools --self-test"
    printfn ""
    printfn "Examples:"
    printfn "  IosSandboxExplorer.Tools \"ls\""
    printfn "  IosSandboxExplorer.Tools \"pwd\" --host localhost --port 8080"
    printfn ""
    printfn "Python client.py remains available until the F# cutover phase."

let private parseArgs (argv: string[]) : Result<Args, string> =
    let mutable command: string option = None
    let mutable host = "localhost"
    let mutable port = 8080
    let mutable selfTest = false
    let mutable i = 0
    let mutable err: string option = None

    while i < argv.Length && err.IsNone do
        match argv[i] with
        | "--self-test" ->
            selfTest <- true
            i <- i + 1
        | "--host" when i + 1 < argv.Length ->
            host <- argv[i + 1]
            i <- i + 2
        | "--port" when i + 1 < argv.Length ->
            match Int32.TryParse(argv[i + 1]) with
            | true, p ->
                port <- p
                i <- i + 2
            | _ -> err <- Some $"Invalid --port value: {argv[i + 1]}"
        | "--help" | "-h" ->
            err <- Some "help"
        | flag when flag.StartsWith("-") ->
            err <- Some $"Unknown option: {flag}"
        | cmd ->
            match command with
            | Some _ -> err <- Some "Only one command argument is allowed"
            | None ->
                command <- Some cmd
                i <- i + 1

    match err with
    | Some e -> Error e
    | None when selfTest ->
        Ok { Command = None; Host = host; Port = port; SelfTest = true }
    | None ->
        match command with
        | None -> Error "missing command (or pass --self-test)"
        | Some c -> Ok { Command = Some c; Host = host; Port = port; SelfTest = false }

[<EntryPoint>]
let main argv =
    match parseArgs argv with
    | Error "help" ->
        usage ()
        0
    | Error msg ->
        eprintfn "Error: %s" msg
        usage ()
        1
    | Ok args when args.SelfTest ->
        selfTest ()
    | Ok args ->
        runCommand args.Host args.Port args.Command.Value
