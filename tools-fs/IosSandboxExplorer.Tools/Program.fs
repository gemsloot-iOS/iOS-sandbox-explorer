// Scaffold only — feature ports land in later gated phases (client, patcher, signing).
module Program

[<EntryPoint>]
let main argv =
    printfn "IosSandboxExplorer.Tools scaffold OK (net8.0)"
    if argv.Length > 0 then
        printfn "args: %s" (String.concat " " argv)
    0
