// Thin helpers over plist-cil for GSA / Developer Portal XML plists.

module IosSandboxExplorer.ApplePlist

open System
open System.IO
open System.Text
open Claunia.PropertyList

let nsString (s: string) = NSString(s) :> NSObject
let nsData (b: byte[]) = NSData(b) :> NSObject
let nsBool (v: bool) = NSNumber(v) :> NSObject
let nsInt (v: int) = NSNumber(v) :> NSObject

let nsArray (items: NSObject seq) =
    let a = NSArray()
    for i in items do
        a.Add(i) |> ignore
    a :> NSObject

let dictOf (pairs: (string * NSObject) list) =
    let d = NSDictionary()
    for k, v in pairs do
        d.Add(k, v)
    d

let toXmlBytes (root: NSObject) : byte[] =
    use ms = new MemoryStream()
    PropertyListParser.SaveAsXml(root, ms)
    ms.ToArray()

let parse (data: byte[]) : NSObject =
    use ms = new MemoryStream(data)
    PropertyListParser.Parse(ms)

let parseSpdPlist (data: byte[]) : NSDictionary =
    try
        parse data :?> NSDictionary
    with _ ->
        let stripped = data |> Array.skipWhile (fun b -> b = 0uy) |> fun a ->
            let mutable endIdx = a.Length - 1
            while endIdx >= 0 && (a.[endIdx] = 0uy || Char.IsWhiteSpace(char a.[endIdx])) do
                endIdx <- endIdx - 1
            if endIdx < 0 then [||] else a.[0..endIdx]
        if stripped.Length >= 6 && Encoding.UTF8.GetString(stripped, 0, 6) = "<dict>" then
            let wrapped =
                Encoding.UTF8.GetBytes(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
                    + "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                    + "<plist version=\"1.0\">\n"
                )
                |> fun prefix ->
                    Array.concat
                        [ prefix
                          stripped
                          Encoding.UTF8.GetBytes("\n</plist>") ]
            parse wrapped :?> NSDictionary
        else
            failwith $"Cannot parse SPD plist, first 64 bytes: {BitConverter.ToString(data.[0 .. min 63 (data.Length - 1)])}"

let tryGet (d: NSDictionary) (key: string) : NSObject option =
    if d.ContainsKey(key) then Some(d.ObjectForKey(key)) else None

let asString (o: NSObject) : string option =
    match o with
    | :? NSString as s -> Some(s.ToString())
    | :? NSData as d -> Some(Encoding.UTF8.GetString(d.Bytes))
    | _ ->
        try Some(o.ToString())
        with _ -> None

let asInt (o: NSObject) : int option =
    match o with
    | :? NSNumber as n -> Some(n.ToInt())
    | :? NSString as s ->
        match Int32.TryParse(s.ToString()) with
        | true, v -> Some v
        | _ -> None
    | _ -> None

let asBytes (o: NSObject) : byte[] option =
    match o with
    | :? NSData as d -> Some(d.Bytes)
    | :? NSString as s -> Some(Encoding.UTF8.GetBytes(s.ToString()))
    | _ -> None

let getString (d: NSDictionary) (key: string) : string option =
    tryGet d key |> Option.bind asString

let getInt (d: NSDictionary) (key: string) : int option =
    tryGet d key |> Option.bind asInt

let getBytes (d: NSDictionary) (key: string) : byte[] option =
    tryGet d key |> Option.bind asBytes

let getDict (d: NSDictionary) (key: string) : NSDictionary option =
    tryGet d key
    |> Option.bind (function
        | :? NSDictionary as x -> Some x
        | _ -> None)

let getArray (d: NSDictionary) (key: string) : NSObject list =
    match tryGet d key with
    | Some(:? NSArray as a) -> [ for i in 0 .. int a.Count - 1 -> a.[i] ]
    | _ -> []

/// Flatten NSDictionary to a string-keyed map for Status / simple portal fields.
let flattenStrings (d: NSDictionary) : Map<string, string> =
    [ for k in d.Keys do
          let key = string k
          match d.ObjectForKey(key) with
          | :? NSString as s -> yield key, s.ToString()
          | :? NSNumber as n -> yield key, n.ToString()
          | :? NSData as data -> yield key, Convert.ToBase64String(data.Bytes)
          | _ -> () ]
    |> Map.ofList
