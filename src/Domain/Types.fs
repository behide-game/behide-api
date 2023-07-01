namespace BehideApi.Types

open System

type Email = Email of string

[<RequireQualifiedAccess>]
type AuthProvider =
    | Discord
    | Google
    | Microsoft

type AuthConnection = {
    NameIdentifier: string
    Email: Email
    Provider: AuthProvider
}

type UserId = UserId of Guid
type User = {
    Id: UserId
    Name: string
    AuthConnections: AuthConnection []
}