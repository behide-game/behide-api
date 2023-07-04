module BehideApi.API.Authentication

open System
open System.Web
open System.Security.Claims
open System.IdentityModel.Tokens.Jwt
open Microsoft.AspNetCore.Http
open FsToolkit.ErrorHandling

open Falco
open Falco.Routing
open Falco.Security
open Falco.Helpers

open BehideApi
open BehideApi.Types
open BehideApi.Repository
open BehideApi.API.Common


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



// ------------------------- Sign up -------------------------

let createAccount (ctx: HttpContext) = taskResult {
    let query = Request.getQuery ctx
    let! finalRedirectUri =
        query.TryGetString "redirect_uri"
        |> Result.ofOption (Response.badRequest "Cannot find redirect_uri query")
        |> Result.map HttpUtility.UrlEncode

    let redirectUri = sprintf "/auth/create-account/complete/%s" finalRedirectUri

    return connectWithProviderAndRedirect redirectUri ctx |> TaskResult.eitherId
}

let completeCreateAccount (ctx: HttpContext) = taskResult {
    // Retrieve info
    let route = Request.getRoute ctx
    let! redirectUri =
        route.TryGetStringNonEmpty "final_redirect_uri"
        |> Result.ofOption (Response.badRequest "Cannot find the final_redirect_uri in route")
        |> Result.map HttpUtility.UrlDecode

    let! provider =
        route.GetString("provider", "discord") |> function
        | "discord" -> Ok AuthProvider.Discord
        | "google" -> Ok AuthProvider.Google
        | _ -> Error (Response.badRequest "Incorrect provider")

    let! email =
        Auth.getClaimValue ClaimTypes.Email ctx
        |> Result.ofOption (Response.unauthorized "Cannot find email claim")
        |> Result.map Email.parse

    let! nameIdentifier =
        Auth.getClaimValue ClaimTypes.NameIdentifier ctx
        |> Result.ofOption (Response.unauthorized "Cannot find name identifier claim")


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
            |> TaskResult.mapError (fun error -> Response.internalServerError error)

        finalRedirectQuery.Add("access_token", accessToken)
        finalRedirectQuery.Add("refresh_token", refreshToken)

        ()
    | [ _user ], _ -> finalRedirectQuery.Add("failed", "user-already-exists")
    | [], [ _user ] -> finalRedirectQuery.Add("failed", "user-with-same-email-exists")
    | _ -> finalRedirectQuery.Add("failed", "many-users-already-exist")

    finalRedirectUri.Query <- finalRedirectQuery.ToString()

    return Response.redirectTemporarily finalRedirectUri.Uri.AbsoluteUri ctx
}



// ------------------------- Login -------------------------

let login (ctx: HttpContext) = taskResult {
    let query = Request.getQuery ctx
    let! escapedFinalRedirectUri =
        query.TryGetString "redirect_uri"
        |> Result.ofOption (Response.badRequest "Cannot find redirect_uri query")
        |> Result.map HttpUtility.UrlEncode

    let redirectUri = sprintf "/auth/login/complete/%s" escapedFinalRedirectUri

    return connectWithProviderAndRedirect redirectUri ctx |> TaskResult.eitherId
}

let completeLogin (ctx: HttpContext) = taskResult {
    let route = Request.getRoute ctx
    let! redirectUri =
        route.TryGetString "final_redirect_uri"
        |> Result.ofOption (Response.badRequest "Cannot find the final_redirect_uri in route")
        |> Result.map HttpUtility.UrlDecode

    let! nameIdentifier =
        Auth.getClaimValue ClaimTypes.NameIdentifier ctx
        |> Result.ofOption (Response.unauthorized "Cannot find name identifier claim")

    let! user =
        Database.Users.findByUserNameIdentifier nameIdentifier
        |> Task.map List.tryHead
        |> Task.map (Result.ofOption (Response.notFound "User not found, try to sign up"))

    // Generate JWT token and it to redirectUri's query
    let finalRedirectUri = new UriBuilder(redirectUri)

    let! (accessToken, refreshToken) =
        JWT.generateTokensForUser user
        |> TaskResult.mapError (sprintf "Failed to generate jwt token: %s")
        |> TaskResult.mapError Response.internalServerError

    let query = HttpUtility.ParseQueryString(finalRedirectUri.Query)
    query.Add("access_token", accessToken)
    query.Add("refresh_token", refreshToken)
    finalRedirectUri.Query <- query.ToString()

    return Response.redirectTemporarily finalRedirectUri.Uri.AbsoluteUri ctx
}



// ------------------------- Refresh token -------------------------

let refreshToken (ctx: HttpContext) = taskResult {
    let query = Request.getQuery ctx
    let! accessToken =
        "access_token"
        |> query.TryGetStringNonEmpty
        |> Result.ofOption (Response.badRequest "Cannot find access_token in query")
    let! refreshToken =
        "refresh_token"
        |> query.TryGetStringNonEmpty
        |> Result.ofOption (Response.badRequest "Cannot find refresh_token in query")

    let tokenHandler = JwtSecurityTokenHandler()
    let! jwtToken =
        tokenHandler.ReadJwtToken(accessToken)
        |> TaskResult.retn
        |> TaskResult.catch (fun _ -> Response.badRequest "Failed to read access token")

    let claims = jwtToken.Claims |> Seq.map (fun claim -> claim.Type, claim.Value)

    let! userId =
        claims
        |> Seq.tryFind (fst >> (=) ClaimTypes.NameIdentifier)
        |> Result.ofOption (Response.unauthorized "Unauthorized")
        |> Result.bind (snd >> UserId.tryParse >> Result.ofOption (Response.unauthorized "Unauthorized, failed to parse name identifier"))

    let! user =
        userId
        |> Database.Users.findByUserId
        |> Task.map List.tryHead
        |> TaskResult.ofOption (Response.notFound "User not found")

    let! (accessToken, refreshToken) =
        JWT.refreshTokenForUser user accessToken refreshToken
        |> TaskResult.mapError (fun error -> Response.internalServerError error)

    let response = DTO.Auth.RefreshToken.createResponse accessToken refreshToken

    return Response.ofJson response ctx
}


let endpoints = [
    get "/auth/create-account" (createAccount |> Handler.fromTRHandler)
    get "/auth/create-account/complete/{final_redirect_uri}/{provider:alpha}"
        (Request.ifAuthenticated
            (completeCreateAccount |> Handler.fromTRHandler)
            (Response.unauthorized "Unauthorized"))

    get "/auth/login" (login |> Handler.fromTRHandler)
    get "/auth/login/complete/{final_redirect_uri}/{provider:alpha}"
        (Request.ifAuthenticated
            (completeLogin |> Handler.fromTRHandler)
            (Response.unauthorized "Unauthorized"))

    post "/auth/refresh-token" (refreshToken |> Handler.fromTRHandler)
]