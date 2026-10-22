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
    /// Last Client-Info used when generating headers (for GSA HTTP header).
    abstract LastClientInfo: string with get

let headersToMap (h: AnisetteHeaders) : Map<string, string> =
    Map.ofList
        [ "X-Apple-I-Client-Time", h.ClientTime
          "X-Apple-I-TimeZone", h.TimeZone
          "X-Apple-Locale", h.Locale
          "X-Apple-I-MD", h.Md
          "X-Apple-I-MD-M", h.MdM
          "X-Apple-I-MD-LU", h.MdLu
          "X-Apple-I-MD-RINFO", h.MdRinfo
          "X-Apple-I-SRL-NO", h.SrlNo
          "X-Mme-Device-Id", h.DeviceId
          "X-Mme-Client-Info", h.ClientInfo ]

let generateCpd (provider: IAnisetteProvider) : Map<string, obj> =
    let h = provider.GenerateHeaders()
    let baseMap = headersToMap h
    baseMap
    |> Map.toList
    |> List.map (fun (k, v) -> k, box v)
    |> List.append
        [ "bootstrap", box true
          "icscrec", box true
          "pbe", box false
          "prkgen", box true
          "svct", box "iCloud"
          "loc", box "en_US" ]
    |> Map.ofList

type HttpAnisetteProvider(serverUrl: string, ?httpClient: HttpClient) =
    let url = serverUrl.TrimEnd('/')
    let client = defaultArg httpClient (AppleTls.createClient ())
    let ownsClient = httpClient.IsNone
    let deviceId = Guid.NewGuid().ToString("D").ToUpperInvariant()
    let localUserId = Guid.NewGuid().ToString("D").ToUpperInvariant()
    let mutable lastClientInfo = clientInfoFallback

    interface IDisposable with
        member _.Dispose() = if ownsClient then client.Dispose()

    interface IAnisetteProvider with
        member _.LastClientInfo = lastClientInfo

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
                        + "On Linux, start an HTTP anisette server (F# does not embed Unicorn ADI).\n"
                        + $"Detail: {ex.Message}"
                    )
                )
            | ex -> raise (Exception($"Anisette fetch failed: {ex.Message}", ex))

        member this.GenerateHeaders() =
            let data = (this :> IAnisetteProvider).Fetch()
            let h = buildHeadersFromAnisette data deviceId localUserId
            lastClientInfo <- h.ClientInfo
            h

/// Native macOS helper (tools/anisette_helper) — optional; not required for CI.
type NativeAnisetteProvider(helperBin: string) =
    let mutable deviceId = Guid.NewGuid().ToString("D").ToUpperInvariant()
    let mutable localUserId = Guid.NewGuid().ToString("D").ToUpperInvariant()
    let mutable lastClientInfo = clientInfoFallback
    let mutable extraClientInfo: string option = None
    let mutable extraSrl: string option = None

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

    do
        let data = runHelper ()
        deviceId <- data |> Map.tryFind "X-Mme-Device-Id" |> Option.defaultValue deviceId
        localUserId <- data |> Map.tryFind "X-Apple-I-MD-LU" |> Option.defaultValue localUserId
        extraClientInfo <- data |> Map.tryFind "X-Mme-Client-Info"
        extraSrl <- data |> Map.tryFind "X-Apple-SRL-NO"

    interface IAnisetteProvider with
        member _.LastClientInfo = lastClientInfo

        member _.Fetch() =
            let raw = runHelper ()
            Map.ofList
                [ "X-Apple-I-MD", raw.["X-Apple-I-MD"]
                  "X-Apple-I-MD-M", raw.["X-Apple-I-MD-M"]
                  "X-Mme-Device-Id", deviceId ]

        member _.GenerateHeaders() =
            let raw = runHelper ()
            let merged =
                raw
                |> Map.add "X-Mme-Device-Id" deviceId
                |> (fun m ->
                    match extraClientInfo with
                    | Some ci -> Map.add "X-Mme-Client-Info" ci m
                    | None -> m)
                |> (fun m ->
                    match extraSrl with
                    | Some s -> Map.add "X-Apple-I-SRL-NO" s m
                    | None -> m)
            let h = buildHeadersFromAnisette merged deviceId localUserId
            lastClientInfo <- h.ClientInfo
            h

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
