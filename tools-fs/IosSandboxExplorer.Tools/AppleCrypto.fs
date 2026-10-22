// Crypto helpers from apple_account.py AppleAuth — offline-testable pieces.

module IosSandboxExplorer.AppleCrypto

open System
open System.Security.Cryptography
open System.Text
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Modes
open Org.BouncyCastle.Crypto.Engines

/// Apple GSA password derivation (s2k / s2k_fo) prior to SRP.
let encryptPassword (password: string) (salt: byte[]) (iterations: int) (protocol: string) : byte[] =
    let mutable p = SHA256.HashData(Encoding.UTF8.GetBytes(password))
    if protocol = "s2k_fo" then
        p <- Encoding.UTF8.GetBytes(Convert.ToHexString(p).ToLowerInvariant())
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

/// AES-256-GCM decrypt of SPD (et=4) — 12-byte nonce (AesGcm).
let decryptSpdGcm (sessionKey: byte[]) (data: byte[]) : byte[] =
    let key = HMACSHA256.HashData(sessionKey, Encoding.UTF8.GetBytes("extra data key:"))
    let nonce = HMACSHA256.HashData(sessionKey, Encoding.UTF8.GetBytes("extra data iv:")).[0..11]
    let plaintext = Array.zeroCreate (data.Length - 16)
    let tag = data.[data.Length - 16 ..]
    let ciphertext = data.[0 .. data.Length - 17]
    use gcm = new AesGcm(key, 16)
    gcm.Decrypt(nonce, ciphertext, tag, plaintext)
    plaintext

/// AES-256-GCM decrypt of app tokens: 3-byte header AAD + 16-byte nonce.
/// .NET AesGcm only allows 12-byte nonces; BouncyCastle matches Python cryptography.
let decryptGcmAppToken (key: byte[]) (data: byte[]) : byte[] =
    if data.Length < 3 + 16 + 16 then
        invalidArg "data" "app-token ciphertext too short"
    let header = data.[0..2]
    let nonce = data.[3 .. 18]
    let ciphertextWithTag = data.[19..]
    let cipher = GcmBlockCipher(AesEngine())
    let parameters = AeadParameters(KeyParameter(key), 128, nonce, header)
    cipher.Init(false, parameters)
    let output = Array.zeroCreate (cipher.GetOutputSize(ciphertextWithTag.Length))
    let len = cipher.ProcessBytes(ciphertextWithTag, 0, ciphertextWithTag.Length, output, 0)
    let final = cipher.DoFinal(output, len)
    if len + final < output.Length then output.[0 .. len + final - 1] else output

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

let private encryptGcmAppTokenForTest (key: byte[]) (plain: byte[]) : byte[] =
    let header = [| 0x01uy; 0x00uy; 0x00uy |]
    let nonce = Array.init 16 (fun i -> byte (i + 1))
    let cipher = GcmBlockCipher(AesEngine())
    let parameters = AeadParameters(KeyParameter(key), 128, nonce, header)
    cipher.Init(true, parameters)
    let output = Array.zeroCreate (cipher.GetOutputSize(plain.Length))
    let len = cipher.ProcessBytes(plain, 0, plain.Length, output, 0)
    let final = cipher.DoFinal(output, len)
    let ct = if len + final < output.Length then output.[0 .. len + final - 1] else output
    Array.concat [ header; nonce; ct ]

let selfTest () : int =
    let salt = Encoding.UTF8.GetBytes("saltsalt")
    let d1 = encryptPassword "password" salt 1000 "s2k"
    let d2 = encryptPassword "password" salt 1000 "s2k"
    let s2kExpected = "df0cf908e4af68fb811481506af2634ea243d28707e373ccfb07a4c9b2044df6"
    let s2kFoExpected = "7af7350da3a7820956b54f4090f61df8aa167bc25bbb7b4d34a944456387de38"
    if d1.Length <> 32 || d1 <> d2 then
        eprintfn "self-test-apple-crypto FAIL: s2k not deterministic"
        1
    elif Convert.ToHexString(d1).ToLowerInvariant() <> s2kExpected then
        eprintfn "self-test-apple-crypto FAIL: s2k vector mismatch"
        1
    else
        let dFo = encryptPassword "password" salt 1000 "s2k_fo"
        if Convert.ToHexString(dFo).ToLowerInvariant() <> s2kFoExpected then
            eprintfn "self-test-apple-crypto FAIL: s2k_fo vector mismatch"
            1
        else
            let sessionKey = SHA256.HashData(Encoding.UTF8.GetBytes("session-key-material"))
            let plain = Encoding.UTF8.GetBytes("hello-spd-payload-ok!!")
            let cipher = encryptCbcForTest sessionKey plain
            let round = decryptCbc sessionKey cipher
            if round <> plain then
                eprintfn "self-test-apple-crypto FAIL: CBC round-trip"
                1
            else
                let appPlain = Encoding.UTF8.GetBytes("apptoken-plain-test!!")
                let appBlob = encryptGcmAppTokenForTest sessionKey appPlain
                let appRound = decryptGcmAppToken sessionKey appBlob
                if appRound <> appPlain then
                    eprintfn "self-test-apple-crypto FAIL: app-token GCM (16-byte nonce) round-trip"
                    1
                else
                    printfn
                        "self-test-apple-crypto OK: s2k/s2k_fo vectors + AES-CBC + app-token GCM"
                    0
