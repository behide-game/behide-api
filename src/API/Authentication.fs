module BehideApi.API.Authentication

open System
open System.Web
open System.Net
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


/// 1. Challenge the auth provider in query "provider", the one provided or discord
/// 2. Redirect to the redirectUrl with the provider used (in this format: "{providedRedirectUrl}/{provider:alpha}"")
let connectWithProviderAndRedirect (redirectUrl: string) (provider: string option) (ctx: HttpContext) = taskResult {
    let query = Request.getQuery ctx

    let fallbackProvider = provider |> Option.defaultValue "discord"
    let! provider =
        query.TryGetString "provider"
        |> Option.defaultValue fallbackProvider
        |> AuthProvider.FromString
        |> Result.requireSome (Response.badRequest "Invalid provider")
        |> Result.map AuthProvider.ToString

    return Response.challengeWithRedirect
        provider
        (sprintf "%s/%s" redirectUrl (provider.ToLower()))
        ctx
}



// ------------------------- Sign up ------------------------

let createAccount (ctx: HttpContext) = taskResult {
    let query = Request.getQuery ctx
    let! finalRedirectUri =
        query.TryGetString "redirect_uri"
        |> Result.ofOption (Response.badRequest "Cannot find redirect_uri query")
        |> Result.map HttpUtility.UrlEncode

    let redirectUri = sprintf "/auth/create-account/complete/%s" finalRedirectUri

    return (connectWithProviderAndRedirect redirectUri None |> Handler.fromTRHandler) ctx
}

let completeCreateAccount (ctx: HttpContext) = taskResult {
    // Retrieve info
    let route = Request.getRoute ctx
    let! redirectUri =
        route.TryGetStringNonEmpty "final_redirect_uri"
        |> Result.ofOption (Response.badRequest "Cannot find the final_redirect_uri in route")
        |> Result.map HttpUtility.UrlDecode

    let! provider =
        route.GetString("provider", "discord")
        |> AuthProvider.FromString
        |> Result.requireSome (Response.badRequest "Invalid provider")

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

    let! usersWithSameEmail = Database.Users.findAllByUserEmail email
    let! usersWithSameNameIdentifier = Database.Users.findAllByUserNameIdentifier nameIdentifier

    match usersWithSameNameIdentifier, usersWithSameEmail with
    | [], [] ->
        let userId = UserId.create()
        let userName = "Temp name" // TODO -> Add a default random name

        let accessToken, refreshToken, accessTokenHash, refreshTokenHash =
            JWT.generateTokens userId userName email

        let user: User = {
            Id = userId
            Name = userName
            AccessTokenHash = accessTokenHash
            RefreshTokenHash = refreshTokenHash
            AuthConnections = {
                Email = email
                NameIdentifier = nameIdentifier
                Provider = provider
            } |> Array.singleton
        }

        do! user |> Database.Users.insert


        finalRedirectQuery.Add("access_token", accessToken)
        finalRedirectQuery.Add("refresh_token", refreshToken)

    | [ _user ], _ -> finalRedirectQuery.Add("error", "user-already-exists")
    | [], [ _user ] -> finalRedirectQuery.Add("error", "user-with-same-email-exists")
    | _ -> finalRedirectQuery.Add("error", "many-users-already-exist")

    finalRedirectUri.Query <- finalRedirectQuery.ToString()

    return Response.redirectTemporarily finalRedirectUri.Uri.AbsoluteUri ctx
}



// ------------------------- Log in -------------------------

let logIn (ctx: HttpContext) = taskResult {
    let query = Request.getQuery ctx
    let! escapedFinalRedirectUri =
        query.TryGetString "redirect_uri"
        |> Result.ofOption (Response.badRequest "Cannot find redirect_uri query")
        |> Result.map HttpUtility.UrlEncode

    let redirectUri = sprintf "/auth/log-in/complete/%s" escapedFinalRedirectUri

    return (connectWithProviderAndRedirect redirectUri None |> Handler.fromTRHandler) ctx
}

let completeLogIn (ctx: HttpContext) =
    taskResult {
        let route = Request.getRoute ctx
        let redirectUriOpt =
            route.TryGetString "final_redirect_uri"
            |> Option.map HttpUtility.UrlDecode

        match redirectUriOpt with
        | None -> return Response.badRequest "Cannot find the final_redirect_uri in route" ctx
        | Some redirectUri ->
            let finalRedirectUri = new UriBuilder(redirectUri)

            let! nameIdentifier =
                Auth.getClaimValue ClaimTypes.NameIdentifier ctx
                |> Result.ofOption (finalRedirectUri, HttpStatusCode.BadRequest) // Cannot find name identifier claim

            let! user =
                Database.Users.findAllByUserNameIdentifier nameIdentifier
                |> Task.map List.tryHead
                |> Task.map (Result.ofOption (finalRedirectUri, HttpStatusCode.NotFound))

            // Generate JWT token and put it into redirectUri's query
            let accessToken, refreshToken, accessTokenHash, refreshTokenHash =
                JWT.generateTokens user.Id user.Name user.AuthConnections[0].Email

            do! Database.Users.updateTokenHashes user.Id accessTokenHash refreshTokenHash
                |> TaskResult.mapError (fun _error -> finalRedirectUri, HttpStatusCode.InternalServerError) // Failed to update user tokens

            let query = HttpUtility.ParseQueryString(finalRedirectUri.Query)
            query.Add("access_token", accessToken)
            query.Add("refresh_token", refreshToken)
            finalRedirectUri.Query <- query.ToString()

            return Response.redirectTemporarily finalRedirectUri.Uri.AbsoluteUri ctx
    }
    |> TaskResult.mapError (fun (redirectUri, statusCode) ->
        let query = HttpUtility.ParseQueryString(redirectUri.Query)
        query.Add("error", statusCode |> int |> string)
        redirectUri.Query <- query.ToString()

        Response.redirectTemporarily redirectUri.Uri.AbsoluteUri
    )



// ---------------------- Refresh token ---------------------

let refreshToken (ctx: HttpContext) = taskResult {
    let query = Request.getQuery ctx
    let! rawAccessToken =
        "access_token"
        |> query.TryGetStringNonEmpty
        |> Result.ofOption (Response.badRequest "Cannot find access_token in query")
    let! refreshToken =
        "refresh_token"
        |> query.TryGetStringNonEmpty
        |> Result.ofOption (Response.badRequest "Cannot find refresh_token in query")

    let tokenHandler = JwtSecurityTokenHandler()
    let! accessToken =
        tokenHandler.ReadJwtToken(rawAccessToken)
        |> TaskResult.retn
        |> TaskResult.catch (fun _ -> Response.badRequest "Failed to read access token")

    let! userId =
        accessToken.Claims
        |> Seq.tryFind (fun claim -> claim.Type = ClaimTypes.NameIdentifier)
        |> Result.ofOption (Response.unauthorized "Unauthorized")
        |> Result.bind (fun claim ->
            claim.Value
            |> UserId.tryParse
            |> Result.ofOption (Response.unauthorized "Unauthorized, failed to parse name identifier")
        )

    let! user =
        userId
        |> Database.Users.findByUserId
        |> TaskResult.ofOption (Response.notFound "User not found")


    do! JWT.verifyUserTokens user rawAccessToken refreshToken
        |> Result.mapError (sprintf "Unauthorized, %s" >> Response.unauthorized)

    let newAccessToken, newRefreshToken, newAccessTokenHash, newRefreshTokenHash =
        JWT.generateTokens user.Id user.Name user.AuthConnections[0].Email

    do! Database.Users.updateTokenHashes user.Id newAccessTokenHash newRefreshTokenHash
        |> TaskResult.mapError Response.internalServerError

    let response = DTO.Auth.RefreshToken.createResponse newAccessToken newRefreshToken
    return Response.ofJson response ctx
}


// -------------------- Add auth provider -------------------

let addAuthProvider (ctx: HttpContext) = taskResult {

    // Retrieve query info
    let query = Request.getQuery ctx
    let! escapedFinalRedirectUri =
        query.TryGetString "redirect_uri"
        |> Result.ofOption (Response.badRequest "Cannot find redirect_uri query")
        |> Result.map HttpUtility.UrlEncode

    // Retrieve route info
    let route = Request.getRoute ctx

    let! provider =
        route.TryGetString "provider"
        |> Option.bind AuthProvider.FromString
        |> Result.ofOption (Response.badRequest "provider not found in route")

    let! userId =
        route.TryGetGuid "user_id"
        |> Option.map UserId
        |> Result.ofOption (Response.badRequest "user_id not found in route")


    // Check if user exists
    let! user =
        userId
        |> Database.Users.findByUserId
        |> TaskResult.ofOption (Response.notFound "User not found")

    // Check if provider already used
    do! user.AuthConnections
        |> Array.tryFind (fun authConnection -> authConnection.Provider = provider)
        |> Result.requireNone (Response.badRequest "User already connected to this provider")

    let redirectUri =
        sprintf "/auth/add-provider/complete/%s/%s"
            (userId |> UserId.rawString)
            escapedFinalRedirectUri

    return
        connectWithProviderAndRedirect
            redirectUri
            (provider |> AuthProvider.ToString |> Some)
        |> Handler.fromTRHandler
        |> fun handler -> handler ctx
}

let completeAddAuthProvider (ctx: HttpContext) =
    taskResult {

        // Retrieve route info
        let route = Request.getRoute ctx
        let! redirectUri = result {
            let! uri =
                route.TryGetString "final_redirect_uri"
                |> Option.map HttpUtility.UrlDecode
                |> Result.ofOption (None, HttpStatusCode.BadRequest, "redirect_uri not provided when completing")

            try
                return! UriBuilder(uri).Uri.AbsoluteUri |> Ok
            with _ ->
                return! Error (None, HttpStatusCode.BadRequest, "redirect_uri provided when completing is invalid")
        }

        let! userId =
            route.TryGetGuid "user_id"
            |> Option.map UserId
            |> Result.ofOption (Some redirectUri, HttpStatusCode.BadRequest, "user_id not provided when completing")

        let! provider =
            route.TryGetString "provider"
            |> Option.bind AuthProvider.FromString
            |> Result.ofOption (Some redirectUri, HttpStatusCode.BadRequest, "provider not provided when completing")


        // Retrieve auth info
        let! nameIdentifier =
            Auth.getClaimValue ClaimTypes.NameIdentifier ctx
            |> Result.ofOption (Some redirectUri, HttpStatusCode.BadRequest, "Cannot find name identifier claim")

        let! email =
            Auth.getClaimValue ClaimTypes.Email ctx
            |> Option.map Email.parse
            |> Result.ofOption (Some redirectUri, HttpStatusCode.BadRequest, "Cannot find email claim")


        // Check if auth connection already exists
        let! authConnections =
            userId
            |> Database.Users.getAuthConnections
            |> TaskResult.mapError (fun error ->
                Some redirectUri,
                HttpStatusCode.InternalServerError,
                sprintf "Failed to retrieve auth connections: %s" error
            )
            |> TaskResult.map (Array.filter (fun authConnection -> authConnection.Provider = provider))

        do! authConnections
            |> Result.requireEmpty (
                Some redirectUri,
                HttpStatusCode.Conflict,
                "User already connected with this auth provider"
            )


        // Update user
        let newAuthConnection : AuthConnection =
            { NameIdentifier = nameIdentifier
              Email = email
              Provider = provider }

        do! newAuthConnection
            |> Database.Users.addAuthConnection userId
            |> TaskResult.mapError (fun error ->
                Some redirectUri,
                HttpStatusCode.InternalServerError,
                sprintf "Failed to update user in database: %s" error
            )

        return Response.redirectTemporarily redirectUri ctx
    }
    |> TaskResult.mapError (fun (redirectUriOpt, statusCode, error) ->
        match redirectUriOpt with
        | None -> Response.badRequest error
        | Some redirectUri ->
            let finalRedirectUri = UriBuilder redirectUri

            let query = HttpUtility.ParseQueryString(finalRedirectUri.Query)
            query.Add("status_code", statusCode |> int |> string)
            query.Add("error", error)
            finalRedirectUri.Query <- query.ToString()

            Response.withStatusCode (statusCode |> int)
            >> Response.redirectTemporarily finalRedirectUri.Uri.AbsoluteUri
    )


let endpoints = [

    // Sign up
    get "/auth/create-account" (createAccount |> Handler.fromTRHandler)
    get "/auth/create-account/complete/{final_redirect_uri}/{provider:alpha}"
        (Request.ifAuthenticated
            (completeCreateAccount |> Handler.fromTRHandler)
            (Response.unauthorized "Unauthorized"))

    // Login
    get "/auth/log-in" (logIn |> Handler.fromTRHandler)
    get "/auth/log-in/complete/{final_redirect_uri}/{provider:alpha}"
        (Request.ifAuthenticated
            (completeLogIn |> Handler.fromTRHandler)
            (Response.unauthorized "Unauthorized"))

    // Add auth provider
    get "/auth/add-provider/{user_id:guid}/{provider:alpha}" (addAuthProvider |> Handler.fromTRHandler)
    get "/auth/add-provider/complete/{user_id:guid}/{final_redirect_uri}/{provider:alpha}" (completeAddAuthProvider |> Handler.fromTRHandler)

    post "/auth/refresh-token" (refreshToken |> Handler.fromTRHandler)
]