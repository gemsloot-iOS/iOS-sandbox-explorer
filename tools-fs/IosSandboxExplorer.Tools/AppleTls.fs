// Explicit TLS policy for Apple HTTP calls.
// Python apple_account.py uses requests with verify=False — F# defaults to VERIFY ON.
// Set IOS_SANDBOX_TLS_INSECURE=1 only for local debugging (never in CI).

module IosSandboxExplorer.AppleTls

open System
open System.Net.Http

let private insecureRequested () =
    let v = Environment.GetEnvironmentVariable("IOS_SANDBOX_TLS_INSECURE")
    not (String.IsNullOrWhiteSpace(v))
    && (v = "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase))

/// Create an HttpClient. Certificate validation is ON unless IOS_SANDBOX_TLS_INSECURE=1.
let createClient () : HttpClient =
    let handler = new HttpClientHandler()
    if insecureRequested () then
        eprintfn "[!] IOS_SANDBOX_TLS_INSECURE=1 — TLS certificate validation DISABLED"
        handler.ServerCertificateCustomValidationCallback <-
            HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    new HttpClient(handler, disposeHandler = true)
