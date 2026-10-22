// Apple GSA SRP-6a client — parity with Python `srp` (rfc5054_enable + no_username_in_x).
// NG_2048, SHA-256. Password may be set after construction (PBKDF2-derived bytes).

module IosSandboxExplorer.AppleSrp

open System
open System.Numerics
open System.Security.Cryptography

let private n2048Hex =
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4"
    + "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60"
    + "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF"
    + "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907"
    + "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861"
    + "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB"
    + "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

let N = BigInteger.Parse("0" + n2048Hex, Globalization.NumberStyles.HexNumber)
let g = BigInteger 2

/// Big-endian, no leading zero bytes (Python long_to_bytes parity).
let longToBytes (n: BigInteger) : byte[] =
    if n.IsZero then [| 0uy |]
    else
        let raw = n.ToByteArray(isUnsigned = true, isBigEndian = true)
        let mutable i = 0
        while i < raw.Length - 1 && raw.[i] = 0uy do
            i <- i + 1
        if i = 0 then raw else raw.[i..]

let bytesToLong (b: byte[]) : BigInteger =
    if b.Length = 0 then BigInteger.Zero
    else BigInteger(b, isUnsigned = true, isBigEndian = true)

let private sha256 (data: byte[]) : byte[] = SHA256.HashData(data)

let private concat (parts: byte[] list) =
    let len = parts |> List.sumBy (fun p -> p.Length)
    let buf = Array.zeroCreate len
    let mutable off = 0
    for p in parts do
        Buffer.BlockCopy(p, 0, buf, off, p.Length)
        off <- off + p.Length
    buf

/// H() with optional RFC5054 left-pad to `width` before each integer arg.
let private hashArgs (width: int option) (args: Choice<BigInteger, byte[]> list) : byte[] =
    use h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256)
    for arg in args do
        let data =
            match arg with
            | Choice1Of2 n -> longToBytes n
            | Choice2Of2 b -> b
        match width with
        | Some w when w > data.Length ->
            let padded = Array.zeroCreate w
            Buffer.BlockCopy(data, 0, padded, w - data.Length, data.Length)
            h.AppendData(padded)
        | _ -> h.AppendData(data)
    h.GetHashAndReset()

let private hNxorg (nVal: BigInteger) (gVal: BigInteger) : byte[] =
    let binN = longToBytes nVal
    let binG = longToBytes gVal
    let padding = binN.Length - binG.Length
    let hN = sha256 binN
    let paddedG =
        if padding > 0 then
            let p = Array.zeroCreate (padding + binG.Length)
            Buffer.BlockCopy(binG, 0, p, padding, binG.Length)
            p
        else
            binG
    let hg = sha256 paddedG
    Array.init hN.Length (fun i -> hN.[i] ^^^ hg.[i])

/// x = H(salt, H(":" || password)) — no_username_in_x (Apple).
let private genX (salt: byte[]) (password: byte[]) : BigInteger =
    let inner = sha256 (concat [ [| byte ':' |]; password ])
    bytesToLong (hashArgs None [ Choice2Of2 salt; Choice2Of2 inner ])

let private calculateM
    (nVal: BigInteger)
    (gVal: BigInteger)
    (username: string)
    (salt: byte[])
    (aPub: BigInteger)
    (bPub: BigInteger)
    (kSession: byte[])
    : byte[] =
    use h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256)
    h.AppendData(hNxorg nVal gVal)
    h.AppendData(sha256 (Text.Encoding.UTF8.GetBytes(username)))
    h.AppendData(salt)
    h.AppendData(longToBytes aPub)
    h.AppendData(longToBytes bPub)
    h.AppendData(kSession)
    h.GetHashAndReset()

let private calculateHamk (aPub: BigInteger) (m: byte[]) (kSession: byte[]) : byte[] =
    use h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256)
    h.AppendData(longToBytes aPub)
    h.AppendData(m)
    h.AppendData(kSession)
    h.GetHashAndReset()

let private modN (x: BigInteger) =
    let r = x % N
    if r.Sign < 0 then r + N else r

type User(username: string, ?password: byte[], ?bytesA: byte[]) =
    let nWidth = (longToBytes N).Length
    let k =
        bytesToLong (hashArgs (Some nWidth) [ Choice1Of2 N; Choice1Of2 g ])
    let aSecret =
        match bytesA with
        | Some ba when ba.Length = 256 -> bytesToLong ba
        | Some _ -> invalidArg "bytesA" "256 bytes required for bytes_a"
        | None ->
            let buf = Array.zeroCreate 256
            RandomNumberGenerator.Fill(buf.AsSpan())
            buf.[0] <- buf.[0] ||| 0x80uy
            bytesToLong buf
    let aPub = BigInteger.ModPow(g, aSecret, N)
    let mutable pBytes = defaultArg password [||]
    let mutable authenticated = false
    let mutable sessionKey: byte[] option = None
    let mutable expectedHamk: byte[] option = None

    member _.Username = username
    member _.ABytes = longToBytes aPub
    member _.SetPassword(p: byte[]) = pBytes <- p
    member _.GetSessionKey() =
        if authenticated then sessionKey else None

    member _.ProcessChallenge(salt: byte[], bytesB: byte[]) : byte[] option =
        let bPub = bytesToLong bytesB
        if (bPub % N).IsZero then None
        else
            let u =
                bytesToLong (
                    hashArgs (Some nWidth) [ Choice1Of2 aPub; Choice1Of2 bPub ]
                )
            if u.IsZero then None
            else
                let x = genX salt pBytes
                let v = BigInteger.ModPow(g, x, N)
                let kv = modN (k * v)
                let baseS = modN (bPub - kv)
                let exp = aSecret + u * x
                let s = BigInteger.ModPow(baseS, exp, N)
                let kSess = sha256 (longToBytes s)
                let m = calculateM N g username salt aPub bPub kSess
                let hamk = calculateHamk aPub m kSess
                sessionKey <- Some kSess
                expectedHamk <- Some hamk
                Some m

    member _.VerifySession(hostHamk: byte[]) : bool =
        match expectedHamk, sessionKey with
        | Some expected, Some _ when expected = hostHamk ->
            authenticated <- true
            true
        | _ -> false

/// Offline self-test against vectors from Python srp (rfc5054 + no_username_in_x).
let selfTest () : int =
    let aHex =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        + "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        + "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        + "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    let bHex =
        "53d6e6d4b6f07767156fcebc4c74ab4f1452078f8f76e0a01e5fc7199967cd79767c61f7"
        + "84085818dac42b95e52b54cf78189acf5fd38e874cf874f4e84e65f71217b5460b9bc16a"
        + "fd11dafbc973267e158132f8e6207ffab084d0d98ab50a38ed94c3aea7eeeb4cdf0521bf"
        + "ada6d7a0c33c471c08c56ee037f43d281b79b25d41695d921e55042d6e65e550dcc13e79"
        + "e88942277c693553d37d0a49c95e5259b1f3b49dfb781431f6e1e231df0eb545860fa39e"
        + "cdab104177762fa2972d554af8dbdfefea082cf9eb997bc27653926db2622d85bddbddc4"
        + "64da70f995e779353244bb661c121d0f309a5ffe19d513c0e7ca77e827f129062d6b7cdb"
        + "6c835b9b"
    let aExpected =
        "596282e6519b522719f061994eaf4d339eb96e4b288d72ae44504a2379721496384db51a"
        + "3c74703a523125a6e0f4437d7dd38d5a321770c569822c14ee3997fbc38f09e7e471e7ef"
        + "f87f81b822d97a2c2fbc0f85ee1ffbc45cdfb026d2c4aa98d6887b699e996e39d3a36138"
        + "fc53a2a16ffc0efd8d5bd4016d88969c7401c7671e9b36589211ed4c0d80a32d84e6020a"
        + "ef2b6f659833748f40bea66757ac5e863e2b6fc0ae18bfcce63a634a3af4958d0ace423b"
        + "6e4efc77527050afba924b5a7de9fcb39a53863be3846dacee61381bf54d0ed1aa084306"
        + "64be9dca05a6b1e5ddb9e5047573f5d3ac5ea75dd99f7745d800954722590d15367581ac"
        + "2f7c4c75"
    let mExpected = "dffcb9db4be20a7b4c5ee47136e8d4c3606a3eaea6824dbb1d07115ce1bdc80e"
    let kExpected = "9295556b40ac9650901681e50fd404c664ae75bc5a3032b00588a4e317fddfde"
    let hamkExpected = "a0b51befb6399f12c40085f4f9426d157d0f348f52e06a73dfa9e0dee8a57cd5"
    let password = [| for i in 0..31 -> byte i |]
    let salt = Array.create 16 0x11uy
    let usr =
        User("test@example.com", password = password, bytesA = Convert.FromHexString(aHex))
    let aGot = Convert.ToHexString(usr.ABytes).ToLowerInvariant()
    if aGot <> aExpected then
        eprintfn "self-test-srp FAIL: A mismatch"
        eprintfn "  got  %s" aGot
        eprintfn "  want %s" aExpected
        1
    else
        match usr.ProcessChallenge(salt, Convert.FromHexString(bHex)) with
        | None ->
            eprintfn "self-test-srp FAIL: process_challenge returned None"
            1
        | Some m ->
            let mHex = Convert.ToHexString(m).ToLowerInvariant()
            if mHex <> mExpected then
                eprintfn "self-test-srp FAIL: M mismatch got=%s want=%s" mHex mExpected
                1
            else
                let hamk = Convert.FromHexString(hamkExpected)
                if not (usr.VerifySession(hamk)) then
                    eprintfn "self-test-srp FAIL: verify_session"
                    1
                else
                    match usr.GetSessionKey() with
                    | Some k when Convert.ToHexString(k).ToLowerInvariant() = kExpected ->
                        printfn "self-test-srp OK: NG_2048 SHA256 rfc5054 + no_username_in_x"
                        0
                    | Some k ->
                        eprintfn
                            "self-test-srp FAIL: K mismatch got=%s"
                            (Convert.ToHexString(k).ToLowerInvariant())
                        1
                    | None ->
                        eprintfn "self-test-srp FAIL: no session key after verify"
                        1
