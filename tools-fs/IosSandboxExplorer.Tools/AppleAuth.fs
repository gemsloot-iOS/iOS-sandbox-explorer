// Live Apple GrandSlam (GSA) authentication — SRP-6a, 2FA, Xcode app token.
// Parity with tools/apple_account.py AppleAuth. TLS verification stays ON (AppleTls).

module IosSandboxExplorer.AppleAuth

open System
open System.Net.Http
open System.Security.Cryptography
open System.Text
open System.Threading
open Claunia.PropertyList

let gsaUrl = "https://gsa.apple.com/grandslam/GsService2"
let xcodeVersion = "15.2 (15C500b)"
let userAgentGsa = "akd/1.0 CFNetwork/1494 Darwin/23.4.0"
let clientInfoFallback =
    "<MacBookPro15,1> <Mac OS X;13.5;22G74> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"

type AuthResult =
    { Adsid: string
      IdmsToken: string
      SessionKey: byte[]
      Cookie: byte[]
      Status: NSDictionary }

type AppleAuthSession(anisette: Anisette.IAnisetteProvider, ?httpClient: HttpClient) =
    let client = defaultArg httpClient (AppleTls.createClient ())
    let ownsClient = httpClient.IsNone
    let mutable adsid: string option = None
    let mutable idmsToken: string option = None
    let mutable sessionKey: byte[] option = None
    let mutable cookie: byte[] option = None
    let mutable xcodeToken: string option = None

    interface IDisposable with
        member _.Dispose() = if ownsClient then client.Dispose()

    member _.Anisette = anisette
    member _.Adsid = adsid
    member _.IdmsToken = idmsToken
    member _.SessionKey = sessionKey
    member _.Cookie = cookie
    member _.XcodeToken = xcodeToken

    member private _.CpdAsNsDict() : NSDictionary =
        let cpd = Anisette.generateCpd anisette
        let d = NSDictionary()
        for KeyValue(k, v) in cpd do
            match v with
            | :? bool as b -> d.Add(k, ApplePlist.nsBool b)
            | :? string as s -> d.Add(k, ApplePlist.nsString s)
            | :? int as i -> d.Add(k, ApplePlist.nsInt i)
            | other -> d.Add(k, ApplePlist.nsString (string other))
        d

    member private this.GsaRequest(params': (string * NSObject) list, ?timeoutSec: int) : NSDictionary =
        let timeout = defaultArg timeoutSec 30
        // Single CPD fetch so OTP / device id stay consistent for this request.
        let req = NSDictionary()
        req.Add("cpd", this.CpdAsNsDict())
        for k, v in params' do
            req.Add(k, v)
        let body =
            ApplePlist.dictOf
                [ "Header", ApplePlist.dictOf [ "Version", ApplePlist.nsString "1.0.1" ]
                  "Request", req ]
        let xml = ApplePlist.toXmlBytes body
        let clientInfo =
            try
                anisette.LastClientInfo
            with _ ->
                clientInfoFallback
        use content = new ByteArrayContent(xml)
        content.Headers.ContentType <- Headers.MediaTypeHeaderValue.Parse("text/x-xml-plist")
        use reqMsg = new HttpRequestMessage(HttpMethod.Post, gsaUrl)
        reqMsg.Content <- content
        reqMsg.Headers.TryAddWithoutValidation("Accept", "text/x-xml-plist") |> ignore
        reqMsg.Headers.TryAddWithoutValidation("User-Agent", userAgentGsa) |> ignore
        reqMsg.Headers.TryAddWithoutValidation("X-MMe-Client-Info", clientInfo) |> ignore
        use cts = new CancellationTokenSource(TimeSpan.FromSeconds(float timeout))
        use resp = client.Send(reqMsg, cts.Token)
        let bytes = resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
        let parsed =
            try
                ApplePlist.parse bytes :?> NSDictionary
            with _ ->
                let preview = Encoding.UTF8.GetString(bytes, 0, min 500 bytes.Length)
                failwith $"GSA returned non-plist response (HTTP {int resp.StatusCode}):\n{preview}"
        match ApplePlist.getDict parsed "Response" with
        | Some r -> r
        | None -> parsed

    member this.Authenticate(username: string, password: string) : AuthResult =
        printfn "[*] GSA: Sending SRP init..."
        let usr = AppleSrp.User(username)
        let aBytes = usr.ABytes
        let initResp =
            this.GsaRequest(
                [ "A2k", ApplePlist.nsData aBytes
                  "ps",
                  ApplePlist.nsArray
                      [ ApplePlist.nsString "s2k"
                        ApplePlist.nsString "s2k_fo" ]
                  "u", ApplePlist.nsString username
                  "o", ApplePlist.nsString "init" ]
            )
        let statusInit =
            ApplePlist.getDict initResp "Status" |> Option.defaultWith (fun () -> NSDictionary())
        let ecInit = ApplePlist.getInt statusInit "ec" |> Option.defaultValue -1
        if ecInit <> 0 then
            let em = ApplePlist.getString statusInit "em" |> Option.defaultValue "Unknown error"
            failwith $"GSA init failed (ec={ecInit}): {em}"

        let protocol =
            ApplePlist.getString initResp "sp" |> Option.defaultValue "s2k"
        let salt =
            ApplePlist.getBytes initResp "s"
            |> Option.defaultWith (fun () -> failwith "GSA init missing salt")
        let iterations =
            ApplePlist.getInt initResp "i"
            |> Option.defaultWith (fun () -> failwith "GSA init missing iterations")
        let bytesB =
            ApplePlist.getBytes initResp "B"
            |> Option.defaultWith (fun () -> failwith "GSA init missing B")
        let c =
            ApplePlist.tryGet initResp "c"
            |> Option.defaultWith (fun () -> failwith "GSA init missing c")

        printfn "[*] GSA: Computing SRP proof..."
        let derived = AppleCrypto.encryptPassword password salt iterations protocol
        usr.SetPassword(derived)
        match usr.ProcessChallenge(salt, bytesB) with
        | None -> failwith "SRP challenge failed — wrong password?"
        | Some m1 ->
            let completeResp =
                this.GsaRequest(
                    [ "c", c
                      "M1", ApplePlist.nsData m1
                      "u", ApplePlist.nsString username
                      "o", ApplePlist.nsString "complete" ]
                )
            let status =
                ApplePlist.getDict completeResp "Status"
                |> Option.defaultWith (fun () -> NSDictionary())
            let ec = ApplePlist.getInt status "ec" |> Option.defaultValue -1
            if ec <> 0 then
                let em = ApplePlist.getString status "em" |> Option.defaultValue "Unknown error"
                match ec with
                | -20101 -> failwith "Invalid Apple ID or password"
                | -22406 -> failwith "Apple ID locked for security reasons"
                | _ -> failwith $"GSA complete failed (ec={ec}): {em}"

            let m2 =
                ApplePlist.getBytes completeResp "M2"
                |> Option.defaultWith (fun () -> failwith "GSA complete missing M2")
            if not (usr.VerifySession(m2)) then
                failwith "SRP server proof (M2) verification failed"

            let sk =
                usr.GetSessionKey()
                |> Option.defaultWith (fun () -> failwith "SRP session key missing")
            let et = ApplePlist.getInt completeResp "et" |> Option.defaultValue 2
            let spdRaw =
                ApplePlist.getBytes completeResp "spd"
                |> Option.defaultWith (fun () -> failwith "GSA complete missing spd")
            printfn "[*] GSA: Decrypting spd (et=%d, %d bytes)..." et spdRaw.Length

            let tryParse (bytes: byte[]) = ApplePlist.parseSpdPlist bytes

            let spd =
                let first =
                    try
                        if et = 4 then AppleCrypto.decryptSpdGcm sk spdRaw
                        else AppleCrypto.decryptCbc sk spdRaw
                    with ex ->
                        raise (Exception($"spd decrypt primary failed: {ex.Message}", ex))
                try
                    tryParse first
                with _ ->
                    let second =
                        if et = 4 then AppleCrypto.decryptCbc sk spdRaw
                        else AppleCrypto.decryptSpdGcm sk spdRaw
                    try
                        tryParse second
                    with ex2 ->
                        failwith
                            $"spd decrypt failed (et={et}). First 64 decrypted bytes: {Convert.ToHexString(first.[0 .. min 63 (first.Length - 1)])}. {ex2.Message}"

            let adsidV =
                ApplePlist.getString spd "adsid"
                |> Option.defaultWith (fun () -> failwith "spd missing adsid")
            let idms =
                ApplePlist.getString spd "GsIdmsToken"
                |> Option.defaultWith (fun () -> failwith "spd missing GsIdmsToken")
            let skSpd = ApplePlist.getBytes spd "sk" |> Option.defaultValue sk
            let cookieV =
                ApplePlist.getBytes spd "c"
                |> Option.defaultWith (fun () -> failwith "spd missing cookie c")

            adsid <- Some adsidV
            idmsToken <- Some idms
            sessionKey <- Some skSpd
            cookie <- Some cookieV

            printfn "[+] GSA: Authenticated as %s" username
            { Adsid = adsidV
              IdmsToken = idms
              SessionKey = skSpd
              Cookie = cookieV
              Status = status }

    member _.Needs2fa(status: NSDictionary) : bool =
        match ApplePlist.getString status "au" with
        | Some "trustedDeviceSecondaryAuth"
        | Some "secondaryAuth" -> true
        | _ -> false

    member _.Get2faType(status: NSDictionary) : string =
        match ApplePlist.getString status "au" with
        | Some "trustedDeviceSecondaryAuth" -> "trusted_device"
        | _ -> "sms"

    member private _.IdentityToken() : string =
        match adsid, idmsToken with
        | Some a, Some t -> Convert.ToBase64String(Encoding.UTF8.GetBytes($"{a}:{t}"))
        | _ -> failwith "Not authenticated"

    member private this.TwoFaHeaders() : Map<string, string> =
        let h = anisette.GenerateHeaders()
        Anisette.headersToMap h
        |> Map.add "Content-Type" "text/x-xml-plist"
        |> Map.add "User-Agent" "Xcode"
        |> Map.add "Accept" "text/x-xml-plist"
        |> Map.add "Accept-Language" "en-us"
        |> Map.add "X-Apple-Identity-Token" (this.IdentityToken())
        |> Map.add "X-Apple-App-Info" "com.apple.gs.xcode.auth"
        |> Map.add "X-Xcode-Version" xcodeVersion

    member private _.SendWithHeaders(method: HttpMethod, url: string, headers: Map<string, string>, ?body: byte[], ?jsonBody: string) =
        use req = new HttpRequestMessage(method, url)
        for KeyValue(k, v) in headers do
            if k = "Content-Type" then ()
            else req.Headers.TryAddWithoutValidation(k, v) |> ignore
        match jsonBody with
        | Some j ->
            let c = new StringContent(j, Encoding.UTF8, "application/json")
            req.Content <- c
        | None ->
            match body with
            | Some b ->
                let c = new ByteArrayContent(b)
                match headers |> Map.tryFind "Content-Type" with
                | Some ct -> c.Headers.ContentType <- Headers.MediaTypeHeaderValue.Parse(ct)
                | None -> ()
                req.Content <- c
            | None -> ()
        use cts = new CancellationTokenSource(TimeSpan.FromSeconds(15.0))
        client.Send(req, cts.Token)

    member this.Send2faTrustedDevice() =
        printfn "[*] 2FA: Sending push to trusted devices..."
        let headers = this.TwoFaHeaders()
        use _ =
            this.SendWithHeaders(
                HttpMethod.Get,
                "https://gsa.apple.com/auth/verify/trusteddevice",
                headers
            )
        printfn "[*] 2FA: Check your trusted device for the verification code"

    member this.Submit2faCode(code: string) : bool =
        printfn "[*] 2FA: Submitting code..."
        let headers = this.TwoFaHeaders() |> Map.add "security-code" code
        use resp =
            this.SendWithHeaders(
                HttpMethod.Get,
                "https://gsa.apple.com/grandslam/GsService2/validate",
                headers
            )
        let bytes = resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
        try
            let result = ApplePlist.parse bytes :?> NSDictionary
            let ec = ApplePlist.getInt result "ec" |> Option.defaultValue -1
            if ec = 0 then
                printfn "[+] 2FA: Code accepted!"
                true
            else
                let em = ApplePlist.getString result "em" |> Option.defaultValue "Unknown error"
                printfn "[!] 2FA: Rejected (ec=%d): %s" ec em
                false
        with _ ->
            if int resp.StatusCode = 200 || int resp.StatusCode = 204 then
                printfn "[+] 2FA: Code accepted!"
                true
            else
                printfn "[!] 2FA: Unexpected response (%d)" (int resp.StatusCode)
                false

    member this.Send2faSms(?phoneId: int) =
        let pid = defaultArg phoneId 1
        printfn "[*] 2FA: Requesting SMS code..."
        let headers =
            this.TwoFaHeaders()
            |> Map.add "Content-Type" "application/json"
        let json = sprintf """{"phoneNumber":{"id":%d},"mode":"sms"}""" pid
        use _ =
            this.SendWithHeaders(
                HttpMethod.Put,
                "https://gsa.apple.com/auth/verify/phone/",
                headers,
                jsonBody = json
            )
        printfn "[*] 2FA: SMS sent to your phone"

    member this.Submit2faSmsCode(code: string, ?phoneId: int) : bool =
        let pid = defaultArg phoneId 1
        printfn "[*] 2FA: Submitting SMS code..."
        let headers =
            this.TwoFaHeaders()
            |> Map.add "Content-Type" "application/json"
        let json =
            sprintf
                """{"securityCode":{"code":"%s"},"phoneNumber":{"id":%d},"mode":"sms"}"""
                code
                pid
        use resp =
            this.SendWithHeaders(
                HttpMethod.Post,
                "https://gsa.apple.com/auth/verify/phone/securitycode",
                headers,
                jsonBody = json
            )
        if int resp.StatusCode = 200 || int resp.StatusCode = 204 then
            printfn "[+] 2FA: SMS code accepted!"
            true
        else
            printfn "[!] 2FA: Rejected (%d)" (int resp.StatusCode)
            false

    member this.GetXcodeToken() : string =
        match sessionKey, cookie, adsid, idmsToken with
        | Some sk, Some c, Some ads, Some idms ->
            let appId = "com.apple.gs.xcode.auth"
            use h = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, sk)
            h.AppendData(Encoding.UTF8.GetBytes("apptokens"))
            h.AppendData(Encoding.UTF8.GetBytes(ads))
            h.AppendData(Encoding.UTF8.GetBytes(appId))
            let checksum = h.GetHashAndReset()

            printfn "[*] Requesting Xcode token..."
            let mutable lastErr: exn option = None
            let mutable result: NSDictionary option = None
            for attempt in 0..2 do
                if result.IsNone then
                    try
                        let r =
                            this.GsaRequest(
                                [ "u", ApplePlist.nsString ads
                                  "app", ApplePlist.nsArray [ ApplePlist.nsString appId ]
                                  "c", ApplePlist.nsData c
                                  "t", ApplePlist.nsString idms
                                  "checksum", ApplePlist.nsData checksum
                                  "o", ApplePlist.nsString "apptokens" ],
                                timeoutSec = 45
                            )
                        result <- Some r
                    with ex ->
                        lastErr <- Some ex
                        printfn "[!] Xcode token attempt %d/3 failed: %s" (attempt + 1) ex.Message
                        if attempt < 2 then Thread.Sleep(3000)

            match result with
            | None ->
                let detail =
                    match lastErr with
                    | Some e -> e.Message
                    | None -> ""
                failwith $"Xcode token request failed after 3 attempts: {detail}"
            | Some r ->
                let status =
                    ApplePlist.getDict r "Status" |> Option.defaultWith (fun () -> NSDictionary())
                let ec = ApplePlist.getInt status "ec" |> Option.defaultValue -1
                if ec <> 0 then
                    let em = ApplePlist.getString status "em" |> Option.defaultValue "Unknown"
                    failwith $"App token request failed (ec={ec}): {em}"
                let et =
                    ApplePlist.getBytes r "et"
                    |> Option.defaultWith (fun () -> failwith "No encrypted token in response")
                let tokenPlistBytes = AppleCrypto.decryptGcmAppToken sk et
                let tokenPlist = ApplePlist.parseSpdPlist tokenPlistBytes
                let token =
                    ApplePlist.getDict tokenPlist "t"
                    |> Option.bind (fun t -> ApplePlist.getDict t appId)
                    |> Option.bind (fun app -> ApplePlist.getString app "token")
                    |> Option.defaultWith (fun () -> failwith "Xcode token not found in decrypted response")
                xcodeToken <- Some token
                printfn "[+] Xcode token obtained"
                token
        | _ -> failwith "Must authenticate first (session_key/cookie missing)"
