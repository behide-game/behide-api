module BehideApi.API.User

open BehideApi.Types
open BehideApi.API.Common

open Falco
open Falco.Helpers
open Falco.Routing
open FsToolkit.ErrorHandling

open Microsoft.AspNetCore.Http

type UserDTO = {
    Id: string
    Name: string
    AuthConnections: {|
        Email: string
        Provider: string
    |} []
}

let handler (ctx: HttpContext) = taskResult {
    let! user = Auth.getBehideUser ctx

    let userDTO = {
        Id = user.Id |> UserId.rawString
        Name = user.Name
        AuthConnections = user.AuthConnections |> Array.map (fun conn -> {|
            Provider = conn.Provider |> AuthProvider.ToString
            Email = conn.Email |> Email.raw
        |})
    }

    return Response.ofJsonOptions jsonOptions userDTO ctx
}

let endpoints = [
    get "/user" (Auth.requireAuth (handler |> Handler.fromTRHandler))
]