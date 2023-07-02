module BehideApi.API.Authentication

open System
open System.Web
open System.Security.Claims
open Microsoft.AspNetCore.Http

open Falco
open Falco.Routing
open Falco.Security
open Falco.Helpers

open BehideApi
open BehideApi.Types
open BehideApi.Repository
open BehideApi.API.Common

open FsToolkit.ErrorHandling


let connectWithProviderAndRedirect (redirectUrl: string) (ctx: HttpContext) = taskResult {
    let query = Request.getQuery ctx
    let! provider =
        query.GetString("provider", "discord") |> function
        | "discord" -> Ok "Discord"
        | "google" -> Ok "Google"
        | _ -> Error (Response.badRequest "Incorrect provider" ctx)

    return Response.challengeWithRedirect
        provider
        (sprintf "%s/%s" redirectUrl (provider.ToLower()))
        ctx
}


let createAccount (ctx: HttpContext) = taskResult {
    let query = Request.getQuery ctx
    let! finalRedirectUri =
        query.TryGetString "redirect_uri" |> function
        | Some uri -> uri |> HttpUtility.UrlEncode |> Ok
        | None -> Error (Response.badRequest "Cannot find redirect_uri query" ctx)

    let redirectUri = sprintf "/auth/create-account/complete/%s" finalRedirectUri

    return connectWithProviderAndRedirect redirectUri ctx |> TaskResult.eitherId
}

let completeCreateAccount (ctx: HttpContext) = taskResult {
    // Retrieve info
    let route = Request.getRoute ctx
    let! redirectUri =
        route.TryGetString "final_redirect_uri" |> function
        | Some uri -> uri |> HttpUtility.UrlDecode |> Ok
        | None -> Error (Response.badRequest "Cannot find the final_redirect_uri in route" ctx)

    let! provider =
        route.GetString("provider", "discord") |> function
        | "discord" -> Ok AuthProvider.Discord
        | "google" -> Ok AuthProvider.Google
        | _ -> Error (Response.badRequest "Incorrect provider" ctx)

    let! email =
        Auth.getClaimValue ClaimTypes.Email ctx |> function
        | Some email -> email |> Email.create |> Ok
        | None -> Error (Response.unauthorized "Cannot find email claim" ctx)

    let! nameIdentifier =
        Auth.getClaimValue ClaimTypes.NameIdentifier ctx |> function
        | Some nameId -> Ok nameId
        | None -> Error (Response.unauthorized "Cannot find name identifier claim" ctx)


    // Work...
    let finalRedirectUri = new UriBuilder(redirectUri)
    let finalRedirectQuery = HttpUtility.ParseQueryString(finalRedirectUri.Query)

    let! usersWithSameEmail = Database.Users.findByUserEmail email
    let! usersWithSameNameIdentifier = Database.Users.findByUserNameIdentifier nameIdentifier
    printfn "%A %A" usersWithSameNameIdentifier.Length usersWithSameEmail.Length
    match usersWithSameNameIdentifier, usersWithSameEmail with
    | [], [] ->
        let user: User = {
            Id = UserId.create()
            Name = "Temp name" // TODO -> Add a default random name
            AuthConnections = {
                Email = email
                NameIdentifier = nameIdentifier
                Provider = provider
            } |> Array.singleton
        }

        do! user |> Database.Users.insert

        // Generate JWT token and it to redirectUri's query
        let! (accessToken, refreshToken) =
            JWT.generateTokensForUser user
            |> TaskResult.mapError (sprintf "Failed to generate jwt token: %s")
            |> TaskResult.mapError (fun error -> Response.internalServerError error ctx)

        finalRedirectQuery.Add("access_token", accessToken)
        finalRedirectQuery.Add("refresh_token", refreshToken)

        ()
    | [ _user ], _ -> finalRedirectQuery.Add("failed", "user-already-exists")
    | [], [ _user ] -> finalRedirectQuery.Add("failed", "user-with-same-email-exists")
    | _ -> finalRedirectQuery.Add("failed", "many-users-already-exist")

    finalRedirectUri.Query <- finalRedirectQuery.ToString()

    return Response.redirectTemporarily finalRedirectUri.Uri.AbsoluteUri ctx
}


let login (ctx: HttpContext) = taskResult {
    let query = Request.getQuery ctx
    let! escapedFinalRedirectUri =
        query.TryGetString "redirect_uri" |> function
        | Some uri -> uri |> HttpUtility.UrlEncode |> Ok
        | None -> Error (Response.badRequest "Cannot find redirect_uri query" ctx)

    let redirectUri = sprintf "/auth/login/complete/%s" escapedFinalRedirectUri

    return connectWithProviderAndRedirect redirectUri ctx |> TaskResult.eitherId
}

let completeLogin (ctx: HttpContext) = taskResult {
    let route = Request.getRoute ctx
    let! redirectUri =
        route.TryGetString "final_redirect_uri" |> function
        | Some uri -> uri |> HttpUtility.UrlDecode |> Ok
        | None -> Error (Response.badRequest "Cannot find the final_redirect_uri in route" ctx)

    let! nameIdentifier =
        Auth.getClaimValue ClaimTypes.NameIdentifier ctx |> function
        | Some nameId -> Ok nameId
        | None -> Error (Response.unauthorized "Cannot find name identifier claim" ctx)

    let! user =
        Database.Users.findByUserNameIdentifier nameIdentifier
        |> Task.map List.tryHead
        |> Task.map (function Some user -> Ok user | None -> Error "User not found, try to sign up")
        |> TaskResult.mapError (fun error -> Response.notFound error ctx)

    // Generate JWT token and it to redirectUri's query
    let finalRedirectUri = new UriBuilder(redirectUri)

    let! (accessToken, refreshToken) =
        JWT.generateTokensForUser user
        |> TaskResult.mapError (sprintf "Failed to generate jwt token: %s")
        |> TaskResult.mapError (fun error -> Response.internalServerError error ctx)

    let query = HttpUtility.ParseQueryString(finalRedirectUri.Query)
    query.Add("access_token", accessToken)
    query.Add("refresh_token", refreshToken)
    finalRedirectUri.Query <- query.ToString()

    return Response.redirectTemporarily finalRedirectUri.Uri.AbsoluteUri ctx
}

let endpoints = [
    get "/auth/create-account" (createAccount >> TaskResult.eitherId)
    get "/auth/create-account/complete/{final_redirect_uri}/{provider:alpha}"
        (Request.ifAuthenticated
            (completeCreateAccount >> TaskResult.eitherId)
            (Response.unauthorized "Unauthorized"))

    get "/auth/login" (login >> TaskResult.eitherId)
    get "/auth/login/complete/{final_redirect_uri}/{provider:alpha}"
        (Request.ifAuthenticated
            (completeLogin >> TaskResult.eitherId)
            (Response.unauthorized "Unauthorized"))
]