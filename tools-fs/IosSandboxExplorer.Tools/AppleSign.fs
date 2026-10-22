// Full Apple ID signing orchestration — GSA → 2FA → portal → zsign/codesign.
// Credentials never written to disk. TLS verify ON via AppleTls.

module IosSandboxExplorer.AppleSign

open System
open System.Diagnostics
open System.IO
open System.IO.Compression
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text
open Claunia.PropertyList

let private which (name: string) : string option =
    let pathEnv = Environment.GetEnvironmentVariable("PATH")
    if String.IsNullOrEmpty(pathEnv) then None
    else
        pathEnv.Split(Path.PathSeparator)
        |> Array.tryPick (fun dir ->
            let p = Path.Combine(dir, name)
            if File.Exists(p) then Some p
            elif OperatingSystem.IsWindows() && File.Exists(p + ".exe") then Some(p + ".exe")
            else None)

let private createAnisette (anisetteUrl: string) (repoRoot: string) : Anisette.IAnisetteProvider =
    match Anisette.tryCreateNativeProvider repoRoot with
    | Some p ->
        printfn "[*] Using native macOS anisette_helper"
        p
    | None ->
        printfn "[*] Using HTTP anisette at %s" anisetteUrl
        new Anisette.HttpAnisetteProvider(anisetteUrl) :> Anisette.IAnisetteProvider

let private readPassword (prompt: string) : string =
    printf "%s" prompt
    // Prefer silent read when interactive; fall back to ReadLine for redirected stdin.
    if Console.IsInputRedirected then
        match Console.ReadLine() with
        | null -> ""
        | s -> s
    else
        let sb = StringBuilder()
        let mutable done' = false
        while not done' do
            let key = Console.ReadKey(true)
            match key.Key with
            | ConsoleKey.Enter ->
                printfn ""
                done' <- true
            | ConsoleKey.Backspace when sb.Length > 0 ->
                sb.Remove(sb.Length - 1, 1) |> ignore
            | ConsoleKey.Backspace -> ()
            | _ when not (Char.IsControl(key.KeyChar)) ->
                sb.Append(key.KeyChar) |> ignore
                printf "*"
            | _ -> ()
        sb.ToString()

let private getBundleIdFromIpa (ipaPath: string) : string =
    use za = ZipFile.OpenRead(ipaPath)
    let entry =
        za.Entries
        |> Seq.tryFind (fun e ->
            let n = e.FullName.Replace('\\', '/')
            n.StartsWith("Payload/")
            && n.EndsWith(".app/Info.plist")
            && n.Split('/').Length = 3)
        |> Option.defaultWith (fun () -> failwith "No Info.plist found in IPA")
    use stream = entry.Open()
    use ms = new MemoryStream()
    stream.CopyTo(ms)
    let root = ApplePlist.parse (ms.ToArray()) :?> NSDictionary
    ApplePlist.getString root "CFBundleIdentifier"
    |> Option.defaultWith (fun () -> failwith "CFBundleIdentifier missing")

let private getDeviceUdid () : string option =
    match which "idevice_id" with
    | None -> None
    | Some bin ->
        try
            let psi =
                ProcessStartInfo(
                    FileName = bin,
                    Arguments = "-l",
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                )
            use p = Process.Start(psi)
            let out' = p.StandardOutput.ReadToEnd()
            p.WaitForExit(10000) |> ignore
            out'.Split([| '\n'; '\r' |], StringSplitOptions.RemoveEmptyEntries)
            |> Array.tryHead
            |> Option.map (fun s -> s.Trim())
        with _ ->
            None

let private decodeCertRaw (o: NSObject option) : byte[] option =
    DeveloperPortal.decodeCertContent o

let private exportPrivateKeyPem (rsa: RSA) : byte[] =
    Encoding.UTF8.GetBytes(rsa.ExportRSAPrivateKeyPem())

let private createP12 (privateKeyPem: byte[]) (certDer: byte[]) (outputPath: string) =
    use rsa = RSA.Create()
    rsa.ImportFromPem(Encoding.UTF8.GetString(privateKeyPem).AsSpan())
    let cert =
        if certDer.Length > 10 && certDer.[0] = byte '-' then
            X509Certificate2.CreateFromPem(Encoding.UTF8.GetString(certDer).AsSpan())
        else
            new X509Certificate2(certDer)
    use withKey = cert.CopyWithPrivateKey(rsa)
    // Empty password PKCS#12 for zsign (parity with Python NoEncryption).
    let p12 = withKey.Export(X509ContentType.Pkcs12, "")
    File.WriteAllBytes(outputPath, p12)
    printfn "[+] Created .p12: %s" outputPath

let private patchIpaBundleId (ipaPath: string) (oldId: string) (newId: string) (workDir: string) : string =
    let patched = Path.Combine(workDir, "patched_bundleid.ipa")
    use zin = ZipFile.OpenRead(ipaPath)
    if File.Exists(patched) then File.Delete(patched)
    use zout = ZipFile.Open(patched, ZipArchiveMode.Create)
    for entry in zin.Entries do
        use src = entry.Open()
        use ms = new MemoryStream()
        src.CopyTo(ms)
        let mutable data = ms.ToArray()
        let name = entry.FullName.Replace('\\', '/')
        if name.EndsWith("/Info.plist") && name.Split('/').Length = 3 then
            try
                let root = ApplePlist.parse data :?> NSDictionary
                match ApplePlist.getString root "CFBundleIdentifier" with
                | Some id when id = oldId ->
                    root.Remove("CFBundleIdentifier") |> ignore
                    root.Add("CFBundleIdentifier", ApplePlist.nsString newId)
                    data <- ApplePlist.toXmlBytes root
                    printfn "[+] Patched Info.plist: %s → %s" oldId newId
                | _ -> ()
            with _ ->
                ()
        let dest = zout.CreateEntry(entry.FullName, CompressionLevel.Optimal)
        use ds = dest.Open()
        ds.Write(data, 0, data.Length)
    patched

let private runZsign (p12: string) (profile: string) (output: string) (ipa: string) : bool =
    match which "zsign" with
    | None -> false
    | Some zsign ->
        let args = $"-k \"{p12}\" -m \"{profile}\" -o \"{output}\" \"{ipa}\""
        printfn "[*] Signing: zsign %s" args
        let psi =
            ProcessStartInfo(
                FileName = zsign,
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            )
        use p = Process.Start(psi)
        let stderr = p.StandardError.ReadToEnd()
        p.WaitForExit()
        if p.ExitCode = 0 then
            printfn "[+] Signed IPA: %s" output
            true
        else
            printfn "[!] zsign failed: %s" stderr
            false

let private signWithCodesign
    (ipaPath: string)
    (outputPath: string)
    (privateKeyPem: byte[])
    (certDer: byte[])
    (profilePath: string)
    (tempDir: string)
    : bool =
    if which "codesign" = None || which "security" = None then false
    else
        try
            let signDir = Path.Combine(tempDir, "sign_work")
            Directory.CreateDirectory(signDir) |> ignore
            ZipFile.ExtractToDirectory(ipaPath, signDir)
            let appPath =
                Directory.GetDirectories(Path.Combine(signDir, "Payload"), "*.app")
                |> Array.tryHead
                |> Option.defaultWith (fun () -> failwith "No .app in IPA")
            // Embed profile
            File.Copy(profilePath, Path.Combine(appPath, "embedded.mobileprovision"), true)
            let keyPemPath = Path.Combine(tempDir, "key.pem")
            let certPemPath = Path.Combine(tempDir, "cert.pem")
            let p12Path = Path.Combine(tempDir, "cert_enc.p12")
            File.WriteAllBytes(keyPemPath, privateKeyPem)
            let certPem =
                if certDer.Length > 10 && certDer.[0] = byte '-' then certDer
                else
                    use c = new X509Certificate2(certDer)
                    let raw: byte[] = c.RawData
                    Encoding.UTF8.GetBytes(
                        "-----BEGIN CERTIFICATE-----\n"
                        + Convert.ToBase64String(raw, Base64FormattingOptions.InsertLineBreaks)
                        + "\n-----END CERTIFICATE-----\n"
                    )
            File.WriteAllBytes(certPemPath, certPem)
            let p12Pass = "tmp_p12_12345"
            let kcPath = Path.Combine(tempDir, "tmp.keychain-db")
            let kcPass = "tmp_kc_pass_12345"
            let openssl = which "openssl" |> Option.defaultValue "openssl"
            let run (file: string) (args: string) =
                let psi =
                    ProcessStartInfo(
                        FileName = file,
                        Arguments = args,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false
                    )
                use p = Process.Start(psi)
                let stderr = p.StandardError.ReadToEnd()
                p.WaitForExit()
                if p.ExitCode <> 0 then failwith stderr
            try
                run openssl $"pkcs12 -export -out \"{p12Path}\" -inkey \"{keyPemPath}\" -in \"{certPemPath}\" -passout pass:{p12Pass} -legacy"
            with _ ->
                run openssl $"pkcs12 -export -out \"{p12Path}\" -inkey \"{keyPemPath}\" -in \"{certPemPath}\" -passout pass:{p12Pass}"
            run "security" $"create-keychain -p {kcPass} \"{kcPath}\""
            run "security" $"set-keychain-settings -lut 21600 \"{kcPath}\""
            run "security" $"unlock-keychain -p {kcPass} \"{kcPath}\""
            run "security" $"import \"{p12Path}\" -k \"{kcPath}\" -P {p12Pass} -T /usr/bin/codesign -T /usr/bin/security"
            run "security" $"set-key-partition-list -S apple-tool:,apple: -s -k {kcPass} \"{kcPath}\""
            // Find identity
            let psiId =
                ProcessStartInfo(
                    FileName = "security",
                    Arguments = $"find-identity -v -p codesigning \"{kcPath}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                )
            use pId = Process.Start(psiId)
            let idOut = pId.StandardOutput.ReadToEnd()
            pId.WaitForExit()
            let identity =
                idOut.Split('\n')
                |> Array.tryPick (fun line ->
                    let idx = line.IndexOf(") ")
                    if idx > 0 && line.Contains("Apple Development") then
                        let rest = line.Substring(idx + 2).Trim()
                        let sp = rest.IndexOf(' ')
                        if sp > 0 then Some(rest.Substring(0, sp)) else Some rest
                    else
                        None)
                |> Option.defaultWith (fun () -> failwith "No signing identity in temp keychain")
            let codesignPath (path: string) (withEnts: bool) =
                let entPath = Path.Combine(appPath, "archived-expanded-entitlements.xcent")
                let ents =
                    if withEnts && File.Exists(entPath) then $" --entitlements \"{entPath}\""
                    else ""
                run
                    "codesign"
                    $"--force --sign {identity} --keychain \"{kcPath}\" --timestamp=none{ents} \"{path}\""
            let fw = Path.Combine(appPath, "Frameworks")
            if Directory.Exists(fw) then
                for item in Directory.GetFileSystemEntries(fw) do
                    if item.EndsWith(".framework") || item.EndsWith(".dylib") then
                        try codesignPath item false with _ -> ()
            codesignPath appPath true
            if File.Exists(outputPath) then File.Delete(outputPath)
            ZipFile.CreateFromDirectory(signDir, outputPath)
            printfn "[+] Signed IPA: %s" outputPath
            try run "security" $"delete-keychain \"{kcPath}\"" with _ -> ()
            true
        with ex ->
            printfn "[!] codesign step failed: %s" ex.Message
            false

type AppleSigner(anisetteUrl: string, repoRoot: string) =
    let anisette = createAnisette anisetteUrl repoRoot
    let auth = new AppleAuth.AppleAuthSession(anisette)
    let mutable portal: DeveloperPortal.PortalClient option = None
    let mutable privateKey: RSA option = None

    member _.Login(appleId: string, password: string) : bool =
        try
            let result = auth.Authenticate(appleId, password)
            let status = result.Status
            if auth.Needs2fa(status) then
                let faType = auth.Get2faType(status)
                printfn "[*] Two-factor authentication required (%s)" faType
                if faType = "trusted_device" then auth.Send2faTrustedDevice()
                else auth.Send2faSms()
                let mutable ok = false
                let mutable attempt = 0
                while (not ok) && attempt < 3 do
                    attempt <- attempt + 1
                    printf "Enter 2FA code (attempt %d/3): " attempt
                    let code =
                        match Console.ReadLine() with
                        | null -> ""
                        | s -> s.Trim()
                    if code <> "" then
                        ok <-
                            if faType = "trusted_device" then auth.Submit2faCode(code)
                            else auth.Submit2faSmsCode(code)
                if not ok then
                    printfn "[!] 2FA failed after maximum attempts"
                    false
                else
                    printfn "[*] Re-authenticating after 2FA..."
                    auth.Authenticate(appleId, password) |> ignore
                    auth.GetXcodeToken() |> ignore
                    portal <- Some(new DeveloperPortal.PortalClient(auth))
                    true
            else
                auth.GetXcodeToken() |> ignore
                portal <- Some(new DeveloperPortal.PortalClient(auth))
                true
        with ex ->
            printfn "[!] Authentication failed: %s" ex.Message
            false

    member this.Provision(udid: string, bundleId: string, appName: string) =
        let portal =
            portal |> Option.defaultWith (fun () -> failwith "Not logged in")
        portal.SelectTeam() |> ignore
        portal.RegisterDevice(appName + " Device", udid)
        let certs = portal.ListCertificates()
        if not certs.IsEmpty then
            printfn "[!] Revoking %d existing certificate(s) to free slot..." certs.Length
            for cert in certs do
                match ApplePlist.getString cert "serialNumber" with
                | Some sn -> portal.RevokeCertificate(sn)
                | None -> ()
        let rsa, csrPem = portal.GenerateCsr()
        privateKey <- Some rsa
        let certInfo = portal.SubmitCsr(csrPem)
        let mutable certDer =
            decodeCertRaw (ApplePlist.tryGet certInfo "certContent")
        if certDer.IsNone then
            Threading.Thread.Sleep(1000)
            let listed = portal.ListCertificates()
            let ourPub = rsa.ExportSubjectPublicKeyInfo()
            certDer <-
                listed
                |> List.rev
                |> List.tryPick (fun c ->
                    match decodeCertRaw (ApplePlist.tryGet c "certContent") with
                    | None -> None
                    | Some raw ->
                        try
                            use loaded = new X509Certificate2(raw)
                            use cpub = loaded.GetRSAPublicKey()
                            if cpub <> null && cpub.ExportSubjectPublicKeyInfo() = ourPub then
                                printfn "[+] Matched cert by public key"
                                Some raw
                            else
                                None
                        with _ ->
                            None)
            if certDer.IsNone && not listed.IsEmpty then
                certDer <- decodeCertRaw (ApplePlist.tryGet listed.[listed.Length - 1] "certContent")
                printfn "[!] Using latest cert (no key match found)"
        let appIdObj, actualBundleId = portal.AddAppId(bundleId, appName)
        let appIdObj =
            if ApplePlist.getString appIdObj "appIdId" = None then
                portal.FindAppId(actualBundleId)
                |> Option.defaultWith (fun () -> failwith $"Could not find appIdId for {actualBundleId}")
            else
                appIdObj
        let appIdId =
            ApplePlist.getString appIdObj "appIdId"
            |> Option.defaultWith (fun () -> failwith $"Could not find appIdId for {actualBundleId}")
        let profileBytes = portal.DownloadProvisioningProfile(appIdId)
        let privateKeyPem = exportPrivateKeyPem rsa
        let certBytes =
            certDer |> Option.defaultWith (fun () -> failwith "No certificate DER obtained")
        printfn "[+] Provisioning complete!"
        printfn "    Team ID:    %s" (portal.TeamId |> Option.defaultValue "?")
        printfn "    Bundle ID:  %s" actualBundleId
        printfn "    Device:     %s..." (udid.Substring(0, min 12 udid.Length))
        printfn "    Profile:    %d bytes" profileBytes.Length
        printfn "    Cert:       %d bytes" certBytes.Length
        privateKeyPem, profileBytes, certBytes, actualBundleId

    member this.SignIpa(ipaPath: string, ?outputPath: string, ?udid: string, ?bundleId: string) : string =
        let ipaPath = Path.GetFullPath(ipaPath)
        let mutable output =
            defaultArg outputPath (ipaPath.Replace(".ipa", "_signed.ipa"))
        let mutable bundle =
            match bundleId with
            | Some b when not (String.IsNullOrWhiteSpace b) -> b
            | _ -> getBundleIdFromIpa ipaPath
        let appName =
            let parts = bundle.Split('.')
            if parts.Length = 0 then "App" else parts.[parts.Length - 1]
        let mutable device =
            match udid with
            | Some u when not (String.IsNullOrWhiteSpace u) -> u
            | _ ->
                match getDeviceUdid () with
                | Some u -> u
                | None ->
                    printf "Enter device UDID: "
                    match Console.ReadLine() with
                    | null -> ""
                    | s -> s.Trim()
        if String.IsNullOrWhiteSpace device then
            failwith "Device UDID required"
        let privateKeyPem, profileBytes, certDer, actualBundleId =
            this.Provision(device, bundle, appName)
        let tempDir = Path.Combine(Path.GetTempPath(), "apple_sign_" + Guid.NewGuid().ToString("N"))
        Directory.CreateDirectory(tempDir) |> ignore
        try
            let mutable workIpa = ipaPath
            if actualBundleId <> bundle then
                printfn "[*] Patching IPA bundle ID: %s → %s" bundle actualBundleId
                workIpa <- patchIpaBundleId ipaPath bundle actualBundleId tempDir
                bundle <- actualBundleId
            let p12Path = Path.Combine(tempDir, "cert.p12")
            let profilePath = Path.Combine(tempDir, "profile.mobileprovision")
            createP12 privateKeyPem certDer p12Path
            File.WriteAllBytes(profilePath, profileBytes)
            printfn "[+] Saved provisioning profile: %s" profilePath
            if runZsign p12Path profilePath output workIpa then output
            elif signWithCodesign workIpa output privateKeyPem certDer profilePath tempDir then
                output
            else
                let ws = Path.GetDirectoryName(output)
                let appStem = Path.GetFileNameWithoutExtension(ipaPath)
                let finalP12 = Path.Combine(ws, $"{appStem}_cert.p12")
                let finalProfile = Path.Combine(ws, $"{appStem}.mobileprovision")
                let finalIpa = Path.Combine(ws, $"{appStem}_patched_bundleid.ipa")
                File.Copy(p12Path, finalP12, true)
                File.Copy(profilePath, finalProfile, true)
                if Path.GetFullPath(workIpa) <> Path.GetFullPath(finalIpa) then
                    File.Copy(workIpa, finalIpa, true)
                printfn ""
                printfn "============================================================"
                printfn "[+] Signing materials saved to workspace:"
                printfn "    Certificate:  %s" finalP12
                printfn "    Profile:      %s" finalProfile
                printfn "    Patched IPA:  %s" finalIpa
                printfn ""
                printfn "    Sign with Sideloadly using the .p12 + .mobileprovision"
                printfn "    Or install zsign and run:"
                printfn "      zsign -k %s -m %s -o %s %s" finalP12 finalProfile output finalIpa
                printfn "============================================================"
                finalIpa
        finally
            try Directory.Delete(tempDir, true) with _ -> ()

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
        printfn "    • F# live Apple ID path: IosSandboxExplorer.Tools apple sign --ipa %s" ipaPath
        Ok ipaPath

let findRepoRoot () : string =
    let mutable dir = Directory.GetCurrentDirectory()
    let mutable found: string option = None
    for _ in 1..8 do
        if found.IsNone then
            if File.Exists(Path.Combine(dir, "Makefile"))
               && Directory.Exists(Path.Combine(dir, "tools")) then
                found <- Some dir
            else
                let parent = Directory.GetParent(dir)
                if parent = null then found <- Some(Directory.GetCurrentDirectory())
                else dir <- parent.FullName
    found |> Option.defaultValue (Directory.GetCurrentDirectory())

/// Live Apple ID sign — full GSA/SRP + portal + zsign/codesign path in F#.
let signIpaLive
    (ipaPath: string)
    (outputPath: string option)
    (udid: string option)
    (bundleId: string option)
    (anisetteUrl: string)
    : Result<string, string> =
    if not (File.Exists(ipaPath)) then Error $"IPA not found: {ipaPath}"
    else
        try
            printf "Apple ID: "
            let appleId =
                match Console.ReadLine() with
                | null -> ""
                | s -> s.Trim()
            if String.IsNullOrWhiteSpace appleId then Error "Apple ID required"
            else
                let password = readPassword "Password: "
                if String.IsNullOrEmpty password then Error "Password required"
                else
                    let signer = AppleSigner(anisetteUrl, findRepoRoot ())
                    if not (signer.Login(appleId, password)) then
                        Error "Login failed"
                    else
                        let out =
                            match outputPath, udid, bundleId with
                            | Some o, Some u, Some b -> signer.SignIpa(ipaPath, o, u, b)
                            | Some o, Some u, None -> signer.SignIpa(ipaPath, o, u)
                            | Some o, None, Some b -> signer.SignIpa(ipaPath, outputPath = o, bundleId = b)
                            | None, Some u, Some b -> signer.SignIpa(ipaPath, udid = u, bundleId = b)
                            | Some o, None, None -> signer.SignIpa(ipaPath, o)
                            | None, Some u, None -> signer.SignIpa(ipaPath, udid = u)
                            | None, None, Some b -> signer.SignIpa(ipaPath, bundleId = b)
                            | None, None, None -> signer.SignIpa(ipaPath)
                        if String.IsNullOrEmpty out then Error "Signing produced no output"
                        else Ok out
        with ex ->
            Error ex.Message

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
        printfn "  Start an anisette HTTP server, or on macOS: make anisette_helper"
        printfn "  (F# does not embed Linux Unicorn ADI; HTTP/native helper only.)"
        1
