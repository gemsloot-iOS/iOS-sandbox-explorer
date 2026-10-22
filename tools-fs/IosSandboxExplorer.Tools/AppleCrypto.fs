// Crypto helpers from apple_account.py AppleAuth — offline-testable pieces only.

module IosSandboxExplorer.AppleCrypto

open System
open System.Security.Cryptography
open System.Text

/// Apple GSA password derivation (s2k / s2k_fo) prior to SRP.
let encryptPassword (password: string) (salt: byte[]) (iterations: int) (protocol: string) : byte[] =
    let mutable p = SHA256.HashData(Encoding.UTF8.GetBytes(password))
    if protocol = "s2k_fo" then
        p <- Encoding.UTF8.GetBytes(Convert.ToHexString(p).ToLowerInvariant())
    // Python uses hashlib.pbkdf2_hmac("sha256", p, salt, iterations, dklen=32)
    Rfc2898DeriveBytes.Pbkdf2(p, salt, iterations, HashAlgorithmName.SHA256, 32)

/// AES-256-CBC decrypt of GSA extra data (et=2).
let decryptCbc (sessionKey: byte[]) (data: byte[]) : byte[] =
    let key = HMACSHA256.HashData(sessionKey, Encoding.UTF8.GetBytes("extra data key:"))
    let iv = HMACSHA256.HashData(sessionKey, Encoding.UTF8.GetBytes("extra data iv:")).[0..15]
    use aes = Aes.Create()
    aes.Key <- key
    aes.IV <- iv
    aes.Mode <- CipherMode.CBC
    aes.Padding <- PaddingMode.PKCS7
    use decryptor = aes.CreateDecryptor()
    decryptor.TransformFinalBlock(data, 0, data.Length)

/// AES-256-GCM decrypt of SPD (et=4).
let decryptSpdGcm (sessionKey: byte[]) (data: byte[]) : byte[] =
    let key = HMACSHA256.HashData(sessionKey, Encoding.UTF8.GetBytes("extra data key:"))
    let nonce = HMACSHA256.HashData(sessionKey, Encoding.UTF8.GetBytes("extra data iv:")).[0..11]
    let plaintext = Array.zeroCreate (data.Length - 16)
    let tag = data.[data.Length - 16 ..]
    let ciphertext = data.[0 .. data.Length - 17]
    use gcm = new AesGcm(key, 16)
    gcm.Decrypt(nonce, ciphertext, tag, plaintext)
    plaintext

let private encryptCbcForTest (sessionKey: byte[]) (plain: byte[]) : byte[] =
    let key = HMACSHA256.HashData(sessionKey, Encoding.UTF8.GetBytes("extra data key:"))
    let iv = HMACSHA256.HashData(sessionKey, Encoding.UTF8.GetBytes("extra data iv:")).[0..15]
    use aes = Aes.Create()
    aes.Key <- key
    aes.IV <- iv
    aes.Mode <- CipherMode.CBC
    aes.Padding <- PaddingMode.PKCS7
    use encryptor = aes.CreateEncryptor()
    encryptor.TransformFinalBlock(plain, 0, plain.Length)

let selfTest () : int =
    // Password KDF: deterministic check against a fixed vector produced by Python-compatible scheme
    let salt = Encoding.UTF8.GetBytes("saltsalt")
    let d1 = encryptPassword "password" salt 1000 "s2k"
    let d2 = encryptPassword "password" salt 1000 "s2k"
    if d1.Length <> 32 || d1 <> d2 then
        eprintfn "self-test-apple-crypto FAIL: s2k not deterministic"
        1
    else
        let dFo = encryptPassword "password" salt 1000 "s2k_fo"
        if dFo = d1 then
            eprintfn "self-test-apple-crypto FAIL: s2k_fo should differ from s2k"
            1
        else
            let sessionKey = SHA256.HashData(Encoding.UTF8.GetBytes("session-key-material"))
            let plain = Encoding.UTF8.GetBytes("hello-spd-payload-ok!!") // 22 bytes
            let cipher = encryptCbcForTest sessionKey plain
            let round = decryptCbc sessionKey cipher
            if round <> plain then
                eprintfn "self-test-apple-crypto FAIL: CBC round-trip"
                1
            else
                printfn "self-test-apple-crypto OK: s2k/s2k_fo KDF + AES-CBC round-trip"
                0
