module BehideApi.API.Authentication

open System
open System.Web
open System.Text
open System.Security.Claims
open System.IdentityModel.Tokens.Jwt
open Microsoft.AspNetCore.Http
open Microsoft.IdentityModel.Tokens

open Falco
open Falco.Routing
open Falco.Security
open Falco.Helpers

open BehideApi
open BehideApi.Types
open BehideApi.Common
open BehideApi.API.Common

open FsToolkit.ErrorHandling


let createJwtToken claims =
    let tokenDuration = TimeSpan.FromDays 1

    let credentials = SigningCredentials(
        Config.Auth.JWT.signingKey
        |> Encoding.UTF8.GetBytes
        |> SymmetricSecurityKey,
        SecurityAlgorithms.HmacSha256
    )

    JwtSecurityToken(
        issuer = "https://behide.netlify.app",
        audience = "https://behide.netlify.app",
        claims = claims,
        notBefore = DateTime.Now,
        expires = DateTime.Now + tokenDuration,
        signingCredentials = credentials
    )
    |> JwtSecurityTokenHandler().WriteToken

let createJwtTokenForUser user =
    let userId = user.Id |> (fun (UserId guid) -> guid.ToString())
    let email = user.AuthConnections[0].Email |> (fun (Email str) -> str)

    [ ClaimTypes.NameIdentifier, userId
      ClaimTypes.Name, user.Name
      ClaimTypes.Email, email ]
    |> Seq.map Claim
    |> createJwtToken



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
        | Some email -> email |> Email |> Ok
        | None -> Error (Response.unauthorized "Cannot find email claim" ctx)

    let! nameIdentifier =
        Auth.getClaimValue ClaimTypes.NameIdentifier ctx |> function
        | Some nameId -> Ok nameId
        | None -> Error (Response.unauthorized "Cannot find name identifier claim" ctx)


    // Work...
    let finalRedirectUri = new UriBuilder(redirectUri)

    let! usersWithSameEmail = Database.Users.findByUserEmail email
    match usersWithSameEmail with
    | [] ->
        let user: User = {
            Id = Guid.NewGuid() |> UserId
            Name = "Temp name" // TODO -> Add a default random name
            AuthConnections = {
                Email = email
                NameIdentifier = nameIdentifier
                Provider = provider
            } |> Array.singleton
        }

        do! user |> Database.Users.insert

        // Generate JWT token and it to redirectUri's query
        let token = createJwtTokenForUser user

        let query = HttpUtility.ParseQueryString(finalRedirectUri.Query)
        query.Add("token", token)
        finalRedirectUri.Query <- query.ToString()

        ()
    | [ _user ] -> finalRedirectUri.Path <- finalRedirectUri.Path + "/user-already-exists"
    | _ -> finalRedirectUri.Path <- finalRedirectUri.Path + "/many-users-already-exists"

    return Response.redirectPermanently finalRedirectUri.Uri.AbsoluteUri ctx
}


let login (ctx: HttpContext) = taskResult {
    let query = Request.getQuery ctx
    let! finalRedirectUri =
        query.TryGetString "redirect_uri" |> function
        | Some uri -> uri |> HttpUtility.UrlEncode |> Ok
        | None -> Error (Response.badRequest "Cannot find redirect_uri query" ctx)

    let redirectUri = sprintf "/auth/login/complete/%s" finalRedirectUri

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

    let! user = Database.Users.findByUserNameIdentifier nameIdentifier |> Task.map List.head

    // Generate JWT token and it to redirectUri's query
    let finalRedirectUri = new UriBuilder(redirectUri)

    let token = createJwtTokenForUser user

    let query = HttpUtility.ParseQueryString(finalRedirectUri.Query)
    query.Add("token", token)
    finalRedirectUri.Query <- query.ToString()

    return Response.redirectPermanently finalRedirectUri.Uri.AbsoluteUri ctx
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