module BehideApi.API.User

open BehideApi.API.Common

open Falco
open Falco.Helpers
open Falco.Routing
open FsToolkit.ErrorHandling

open Microsoft.AspNetCore.Http
open System.Security.Claims
open BehideApi.API.Common.Auth

// open Thoth.Json.Net

// type UserDTO = {
//     Id: string
//     Name: string
//     Auth
// }

let handler (principal: ClaimsPrincipal) (ctx: HttpContext) =
    taskResult {
        return Response.ofPlainText ("Hello " + principal.Identity.Name) ctx
    } |> TaskResult.eitherId

let endpoints = [
    get "/user" (requireAuth handler)
]