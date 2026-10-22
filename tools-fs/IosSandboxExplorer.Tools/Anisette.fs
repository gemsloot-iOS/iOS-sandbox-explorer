// Anisette providers (HTTP + optional native macOS helper). Port of apple_account Anisette*.

module IosSandboxExplorer.Anisette

open System
open System.Diagnostics
open System.IO
open System.Net.Http
open System.Text
open System.Text.Json

let defaultAnisetteUrl = "http://localhost:6969"

let private clientInfoFallback =
    "<MacBookPro15,1> <Mac OS X;13.5;22G74> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"

type AnisetteHeaders =
    { ClientTime: string
      TimeZone: string
      Locale: string
      Md: string
      MdM: string
      MdLu: string
      MdRinfo: string
      SrlNo: string
      DeviceId: string
      ClientInfo: string }

exception AnisetteConnectionException of string

let private utcNowIsoZ () =
    DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss") + "Z"

let private jsonToMap (json: string) : Map<string, string> =
    use doc = JsonDocument.Parse(json)
    doc.RootElement.EnumerateObject()
    |> Seq.choose (fun p ->
        match p.Value.ValueKind with
        | JsonValueKind.String -> Some(p.Name, p.Value.GetString())
        | JsonValueKind.Number -> Some(p.Name, p.Value.ToString())
        | _ -> None)
    |> Map.ofSeq

let buildHeadersFromAnisette
    (anisette: Map<string, string>)
    (deviceIdFallback: string)
    (localUserFallback: string)
    : AnisetteHeaders =
    let deviceId =
        anisette |> Map.tryFind "X-Mme-Device-Id" |> Option.defaultValue deviceIdFallback
    let mdLu =
        anisette
        |> Map.tryFind "X-Apple-I-MD-LU"
        |> Option.defaultValue (Convert.ToBase64String(Encoding.UTF8.GetBytes(localUserFallback)))
    let clientInfo =
        anisette
        |> Map.tryFind "X-Mme-Client-Info"
        |> Option.orElse (anisette |> Map.tryFind "X-MMe-Client-Info")
        |> Option.defaultValue clientInfoFallback
    let md = anisette |> Map.tryFind "X-Apple-I-MD" |> Option.defaultValue ""
    let mdM = anisette |> Map.tryFind "X-Apple-I-MD-M" |> Option.defaultValue ""
    { ClientTime = utcNowIsoZ ()
      TimeZone = "UTC"
      Locale = "en_US"
      Md = md
      MdM = mdM
      MdLu = mdLu
      MdRinfo = anisette |> Map.tryFind "X-Apple-I-MD-RINFO" |> Option.defaultValue "17106176"
      SrlNo =
        anisette
        |> Map.tryFind "X-Apple-I-SRL-NO"
        |> Option.orElse (anisette |> Map.tryFind "X-Apple-I-MD-SRL-NO")
        |> Option.defaultValue "0"
      DeviceId = deviceId
      ClientInfo = clientInfo }

type IAnisetteProvider =
    abstract Fetch: unit -> Map<string, string>
    abstract GenerateHeaders: unit -> AnisetteHeaders

type HttpAnisetteProvider(serverUrl: string, ?httpClient: HttpClient) =
    let url = serverUrl.TrimEnd('/')
    let client = defaultArg httpClient (AppleTls.createClient ())
    let ownsClient = httpClient.IsNone
    let deviceId = Guid.NewGuid().ToString("D").ToUpperInvariant()
    let localUserId = Guid.NewGuid().ToString("D").ToUpperInvariant()

    interface IDisposable with
        member _.Dispose() = if ownsClient then client.Dispose()

    interface IAnisetteProvider with
        member _.Fetch() =
            try
                let resp = client.GetAsync(url).GetAwaiter().GetResult()
                resp.EnsureSuccessStatusCode() |> ignore
                let body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                jsonToMap body
            with
            | :? HttpRequestException as ex ->
                raise (
                    AnisetteConnectionException(
                        $"Cannot connect to anisette server at {url}\n"
                        + "On Linux, use Python `anisette` or an HTTP anisette server.\n"
                        + $"Detail: {ex.Message}"
                    )
                )
            | ex -> raise (Exception($"Anisette fetch failed: {ex.Message}", ex))

        member this.GenerateHeaders() =
            let data = (this :> IAnisetteProvider).Fetch()
            buildHeadersFromAnisette data deviceId localUserId

/// Native macOS helper (tools/anisette_helper) — optional; not required for CI.
type NativeAnisetteProvider(helperBin: string) =
    let deviceId = Guid.NewGuid().ToString("D").ToUpperInvariant()
    let localUserId = Guid.NewGuid().ToString("D").ToUpperInvariant()

    let runHelper () =
        if not (File.Exists(helperBin)) then
            raise (
                FileNotFoundException(
                    $"anisette_helper not found at {helperBin}. Build with: make anisette_helper"
                )
            )
        let psi =
            ProcessStartInfo(
                FileName = helperBin,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            )
        use p = Process.Start(psi)
        let stdout = p.StandardOutput.ReadToEnd()
        let stderr = p.StandardError.ReadToEnd()
        p.WaitForExit(15000) |> ignore
        if p.ExitCode <> 0 then
            raise (Exception($"anisette_helper failed (exit {p.ExitCode}): {stderr.Trim()}"))
        jsonToMap stdout

    interface IAnisetteProvider with
        member _.Fetch() =
            let raw = runHelper ()
            Map.ofList
                [ "X-Apple-I-MD", raw.["X-Apple-I-MD"]
                  "X-Apple-I-MD-M", raw.["X-Apple-I-MD-M"] ]

        member _.GenerateHeaders() =
            let raw = runHelper ()
            buildHeadersFromAnisette raw deviceId localUserId

let isMacOS () = OperatingSystem.IsMacOS()

let tryCreateNativeProvider (repoRoot: string) : IAnisetteProvider option =
    if not (isMacOS ()) then None
    else
        let helper = Path.Combine(repoRoot, "tools", "anisette_helper")
        if File.Exists(helper) then Some(NativeAnisetteProvider(helper) :> IAnisetteProvider)
        else None

let checkServer (url: string) (client: HttpClient) : bool =
    try
        use req = new HttpRequestMessage(HttpMethod.Get, url.TrimEnd('/'))
        use resp = client.Send(req)
        resp.IsSuccessStatusCode
    with _ ->
        false

let private tlsInsecureEnvSet () =
    let v = Environment.GetEnvironmentVariable("IOS_SANDBOX_TLS_INSECURE")
    not (String.IsNullOrWhiteSpace(v))

/// Offline self-test using a mock anisette JSON map (no network).
let selfTest () : int =
    if tlsInsecureEnvSet () then
        eprintfn "self-test-anisette FAIL: IOS_SANDBOX_TLS_INSECURE must not be set in CI"
        1
    else
        let mock =
            Map.ofList
                [ "X-Apple-I-MD", "OTPTEST"
                  "X-Apple-I-MD-M", "MIDTEST"
                  "X-Mme-Device-Id", "DEVICE-1"
                  "X-Apple-I-MD-LU", "LUTEST"
                  "X-Mme-Client-Info", clientInfoFallback ]
        let h = buildHeadersFromAnisette mock "FALLBACK" "LOCAL"
        if h.Md <> "OTPTEST" || h.MdM <> "MIDTEST" || h.DeviceId <> "DEVICE-1" then
            eprintfn "self-test-anisette FAIL: header mapping"
            1
        else
            printfn "self-test-anisette OK: header mapping (TLS certificate validation ON by default)"
            0
