namespace BehideApi.Types

open System

type Email = Email of string
module Email =
    let parse rawEmail = Email rawEmail
    let raw (Email email) = email

[<RequireQualifiedAccess>]
type AuthProvider =
    | Discord
    | Google
    | Microsoft

    static member ToString = function
        | Discord -> "discord"
        | Google -> "google"
        | Microsoft -> "microsoft"

type AuthConnection = {
    NameIdentifier: string
    Email: Email
    Provider: AuthProvider
}

type UserId = UserId of Guid
module UserId =
    let tryParse (str: string) =
        Guid.TryParse(str)
        |> function
            | true, guid -> Some (UserId guid)
            | _ -> None
    let create () = Guid.NewGuid() |> UserId
    let raw (UserId guid) = guid
    let rawString (UserId guid) = guid.ToString()
    let rawBytes (UserId guid) = guid.ToByteArray()

type User = {
    Id: UserId
    Name: string
    AuthConnections: AuthConnection []
}

module Auth =
    type Token = {
        UserId: UserId
        AccessToken: string
        RefreshToken: string
    }