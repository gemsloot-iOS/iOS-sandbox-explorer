// Apple Developer Portal API — certificates, profiles, devices, App IDs.
// Parity with tools/apple_account.py DeveloperPortal.

module IosSandboxExplorer.DeveloperPortal

open System
open System.IO
open System.Net.Http
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text
open System.Threading
open Claunia.PropertyList

let devPortalBase = "https://developerservices2.apple.com/services/QH65B2"
let clientId = "XABBG36SBA"
let protocolVersion = "QH65B2"
let xcodeVersion = "15.2 (15C500b)"
let clientInfo =
    "<MacBookPro15,1> <Mac OS X;13.5;22G74> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"

type PortalClient(auth: AppleAuth.AppleAuthSession, ?httpClient: HttpClient) =
    let client = defaultArg httpClient (AppleTls.createClient ())
    let ownsClient = httpClient.IsNone
    let mutable teamId: string option = None

    interface IDisposable with
        member _.Dispose() = if ownsClient then client.Dispose()

    member _.TeamId = teamId

    member private _.Request(action: string, ?params': (string * NSObject) list, ?deviceType: string option) : NSDictionary =
        let requestId = Guid.NewGuid().ToString("D").ToUpperInvariant()
        let body = NSDictionary()
        body.Add("clientId", ApplePlist.nsString clientId)
        body.Add("protocolVersion", ApplePlist.nsString protocolVersion)
        body.Add("requestId", ApplePlist.nsString requestId)
        body.Add("userLocale", ApplePlist.nsArray [ ApplePlist.nsString "en_US" ])
        for k, v in defaultArg params' [] do
            body.Add(k, v)

        let dt = defaultArg deviceType (Some "ios")
        let url =
            match dt with
            | Some d -> $"{devPortalBase}/{d}/{action}?clientId={clientId}"
            | None -> $"{devPortalBase}/{action}?clientId={clientId}"

        let adsid =
            auth.Adsid |> Option.defaultWith (fun () -> failwith "Not authenticated")
        let xcodeTok =
            auth.XcodeToken |> Option.defaultWith (fun () -> failwith "Missing Xcode token")

        let anisetteHeaders = Anisette.headersToMap (auth.Anisette.GenerateHeaders())
        let xml = ApplePlist.toXmlBytes body
        use content = new ByteArrayContent(xml)
        content.Headers.ContentType <- Headers.MediaTypeHeaderValue.Parse("text/x-xml-plist")
        use req = new HttpRequestMessage(HttpMethod.Post, url)
        req.Content <- content
        req.Headers.TryAddWithoutValidation("Accept", "text/x-xml-plist") |> ignore
        req.Headers.TryAddWithoutValidation("Accept-Language", "en-us") |> ignore
        req.Headers.TryAddWithoutValidation("User-Agent", "Xcode") |> ignore
        req.Headers.TryAddWithoutValidation("X-Apple-I-Identity-Id", adsid) |> ignore
        req.Headers.TryAddWithoutValidation("X-Apple-GS-Token", xcodeTok) |> ignore
        req.Headers.TryAddWithoutValidation("X-Xcode-Version", xcodeVersion) |> ignore
        req.Headers.TryAddWithoutValidation("X-Apple-App-Info", "com.apple.gs.xcode.auth") |> ignore
        req.Headers.TryAddWithoutValidation("X-MMe-Client-Info", clientInfo) |> ignore
        for KeyValue(k, v) in anisetteHeaders do
            req.Headers.TryAddWithoutValidation(k, v) |> ignore

        use cts = new CancellationTokenSource(TimeSpan.FromSeconds(45.0))
        use resp = client.Send(req, cts.Token)
        let bytes = resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
        let result =
            try
                ApplePlist.parse bytes :?> NSDictionary
            with _ ->
                let preview = Encoding.UTF8.GetString(bytes, 0, min 500 bytes.Length)
                failwith $"Developer Portal non-plist response (HTTP {int resp.StatusCode}):\n{preview}"

        let rc = ApplePlist.getInt result "resultCode" |> Option.defaultValue 0
        if rc <> 0 then
            let rm = ApplePlist.getString result "resultString" |> Option.defaultValue ""
            let ue = ApplePlist.getString result "userString" |> Option.defaultValue rm
            failwith $"Developer Portal error ({rc}): {ue}"
        result

    member this.ListTeams() : NSDictionary list =
        let r = this.Request("listTeams.action", deviceType = None)
        match ApplePlist.getArray r "teams" with
        | [] -> failwith "No development teams found"
        | items ->
            items
            |> List.choose (function
                | :? NSDictionary as d -> Some d
                | _ -> None)

    member this.SelectTeam(?preferredTeamId: string) : string =
        let teams = this.ListTeams()
        match preferredTeamId with
        | Some tid ->
            let found =
                teams
                |> List.exists (fun t ->
                    ApplePlist.getString t "teamId" = Some tid)
            if not found then failwith $"Team {tid} not found"
            teamId <- Some tid
            printfn "[+] Selected team: %s" tid
            tid
        | None when teams.Length = 1 ->
            let tid =
                ApplePlist.getString teams.[0] "teamId"
                |> Option.defaultWith (fun () -> failwith "team missing teamId")
            let name = ApplePlist.getString teams.[0] "name" |> Option.defaultValue ""
            teamId <- Some tid
            printfn "[+] Team: %s (%s)" name tid
            tid
        | None ->
            printfn "[*] Multiple teams found:"
            teams
            |> List.iteri (fun i t ->
                let name = ApplePlist.getString t "name" |> Option.defaultValue "Unknown"
                let tid = ApplePlist.getString t "teamId" |> Option.defaultValue "?"
                printfn "  [%d] %s (%s)" i name tid)
            let mutable chosen: string option = None
            while chosen.IsNone do
                printf "Select team number: "
                match Console.ReadLine() with
                | null -> ()
                | line ->
                    match Int32.TryParse(line.Trim()) with
                    | true, i when i >= 0 && i < teams.Length ->
                        let tid =
                            ApplePlist.getString teams.[i] "teamId"
                            |> Option.defaultWith (fun () -> failwith "teamId missing")
                        teamId <- Some tid
                        chosen <- Some tid
                    | _ -> printfn "[!] Invalid choice"
            chosen.Value

    member this.RegisterDevice(name: string, udid: string) =
        let tid = teamId |> Option.defaultWith (fun () -> failwith "No team selected")
        printfn "[*] Registering device: %s (%s...)" name (udid.Substring(0, min 12 udid.Length))
        try
            this.Request(
                "addDevice.action",
                [ "teamId", ApplePlist.nsString tid
                  "name", ApplePlist.nsString name
                  "deviceNumber", ApplePlist.nsString udid ]
            )
            |> ignore
            printfn "[+] Device registered: %s" name
        with ex when ex.Message.ToLowerInvariant().Contains("already exists") ->
            printfn "[*] Device already registered"

    member this.ListCertificates() : NSDictionary list =
        let tid = teamId |> Option.defaultWith (fun () -> failwith "No team selected")
        let r =
            this.Request(
                "listAllDevelopmentCerts.action",
                [ "teamId", ApplePlist.nsString tid ]
            )
        ApplePlist.getArray r "certificates"
        |> List.choose (function
            | :? NSDictionary as d -> Some d
            | _ -> None)

    member this.RevokeCertificate(serial: string) =
        let tid = teamId |> Option.defaultWith (fun () -> failwith "No team selected")
        printfn "[*] Revoking certificate: %s" serial
        try
            this.Request(
                "revokeDevelopmentCert.action",
                [ "teamId", ApplePlist.nsString tid
                  "serialNumber", ApplePlist.nsString serial ]
            )
            |> ignore
            printfn "[+] Certificate revoked"
        with ex when ex.Message.Contains("(7252)") ->
            printfn "[*] Certificate already gone (7252)"

    member _.GenerateCsr() : RSA * string =
        let rsa = RSA.Create(2048)
        let req =
            CertificateRequest(
                X500DistinguishedName(""),
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1
            )
        let csrPem = req.CreateSigningRequestPem()
        rsa, csrPem

    member this.SubmitCsr(csrPem: string) : NSDictionary =
        let tid = teamId |> Option.defaultWith (fun () -> failwith "No team selected")
        let machineId = Guid.NewGuid().ToString("D").ToUpperInvariant()
        printfn "[*] Submitting CSR for development certificate..."
        let r =
            this.Request(
                "submitDevelopmentCSR.action",
                [ "teamId", ApplePlist.nsString tid
                  "machineId", ApplePlist.nsString machineId
                  "machineName", ApplePlist.nsString "IOSSandboxExplorer"
                  "csrContent", ApplePlist.nsString csrPem ]
            )
        printfn "[+] Development certificate created"
        ApplePlist.getDict r "certRequest" |> Option.defaultWith (fun () -> NSDictionary())

    member this.ListAppIds() : NSDictionary list =
        let tid = teamId |> Option.defaultWith (fun () -> failwith "No team selected")
        let r = this.Request("listAppIds.action", [ "teamId", ApplePlist.nsString tid ])
        ApplePlist.getArray r "appIds"
        |> List.choose (function
            | :? NSDictionary as d -> Some d
            | _ -> None)

    member this.FindAppId(bundleId: string) : NSDictionary option =
        this.ListAppIds()
        |> List.tryFind (fun a -> ApplePlist.getString a "identifier" = Some bundleId)

    member this.AddAppId(bundleId: string, name: string) : NSDictionary * string =
        let tid = teamId |> Option.defaultWith (fun () -> failwith "No team selected")
        printfn "[*] Creating App ID: %s" bundleId
        try
            let r =
                this.Request(
                    "addAppId.action",
                    [ "teamId", ApplePlist.nsString tid
                      "identifier", ApplePlist.nsString bundleId
                      "name", ApplePlist.nsString name ]
                )
            printfn "[+] App ID created: %s" bundleId
            (ApplePlist.getDict r "appId" |> Option.defaultWith (fun () -> NSDictionary()), bundleId)
        with ex ->
            let err = ex.Message
            if err.ToLowerInvariant().Contains("already exists") then
                printfn "[*] App ID already exists, reusing"
                match this.FindAppId(bundleId) with
                | Some a -> a, bundleId
                | None -> failwith $"App ID exists but could not be listed: {bundleId}"
            elif err.Contains("(9401)") || err.ToLowerInvariant().Contains("is not available") then
                let alt = $"{tid}.{bundleId}"
                printfn "[!] Bundle ID '%s' is taken by another developer" bundleId
                printfn "[*] Trying team-prefixed bundle ID: %s" alt
                try
                    let r2 =
                        this.Request(
                            "addAppId.action",
                            [ "teamId", ApplePlist.nsString tid
                              "identifier", ApplePlist.nsString alt
                              "name", ApplePlist.nsString name ]
                        )
                    printfn "[+] App ID created: %s" alt
                    (ApplePlist.getDict r2 "appId" |> Option.defaultWith (fun () -> NSDictionary()), alt)
                with ex2 ->
                    let e2 = ex2.Message.ToLowerInvariant()
                    if e2.Contains("already exists") || e2.Contains("is not available") then
                        printfn "[*] Alternative App ID already exists, reusing"
                        match this.FindAppId(alt) with
                        | Some a -> a, alt
                        | None -> raise ex2
                    else
                        raise ex2
            else
                raise ex

    member this.DownloadProvisioningProfile(appIdId: string) : byte[] =
        let tid = teamId |> Option.defaultWith (fun () -> failwith "No team selected")
        printfn "[*] Downloading provisioning profile..."
        let r =
            this.Request(
                "downloadTeamProvisioningProfile.action",
                [ "teamId", ApplePlist.nsString tid
                  "appIdId", ApplePlist.nsString appIdId ]
            )
        let profileData =
            ApplePlist.getDict r "provisioningProfile"
            |> Option.defaultWith (fun () -> failwith "No profile data in response")
        match ApplePlist.getBytes profileData "encodedProfile" with
        | Some b -> b
        | None ->
            match ApplePlist.getString profileData "encodedProfile" with
            | Some s -> Convert.FromBase64String(s)
            | None -> failwith "No profile data in response"

let decodeCertContent (raw: NSObject option) : byte[] option =
    match raw with
    | None -> None
    | Some(:? NSData as d) -> Some d.Bytes
    | Some(:? NSString as s) ->
        try Some(Convert.FromBase64String(s.ToString()))
        with _ -> None
    | Some o ->
        match ApplePlist.asBytes o with
        | Some b when b.Length > 0 && b.[0] <> byte '-' -> Some b
        | Some b -> Some b
        | None -> None
