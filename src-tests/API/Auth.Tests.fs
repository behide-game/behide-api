module BehideApi.Tests.API.Auth

open System
open System.Net
open System.Net.Http
open System.IdentityModel.Tokens.Jwt
open System.Security.Claims
open Microsoft.AspNetCore.Http.Extensions
open Microsoft.AspNetCore.Identity
open FsToolkit.ErrorHandling

open Expecto
open Expecto.Flip

open BehideApi.Types
open BehideApi.Tests.Common


let refreshTokensReq (accessToken: string, refreshToken: string) =
    let req = new HttpRequestMessage()
    let uri = UriBuilder("http://localhost:5000/auth/refresh-token")
    let query = new QueryBuilder()
    query.Add("access_token", accessToken)
    query.Add("refresh_token", refreshToken)

    uri.Query <- query.ToQueryString().ToString()
    req.RequestUri <- uri.Uri
    req.Method <- HttpMethod.Post

    req

let refreshTokens client =
    refreshTokensReq
    >> Helpers.Http.send HttpStatusCode.OK client
    >> Helpers.Http.parseResponse<DTO.Auth.RefreshToken.Response>
    >> Task.map (Expect.wantOk "Response should be parsable")

let getClaim claimType (claims: #seq<string * string>) =
    claims
    |> Seq.tryPick (fun (type', value) ->
        match type' = claimType with
        | true -> Some value
        | false -> None
    )
    |> function
        | Some value -> value
        | None -> failtestf "JWT claims should contain %s" claimType



[<Tests>]
let tests = testList "Auth" [
    testList "JWT" [
        testTask "Generate tokens" {
            let userId = UserId.create()
            let userName = "Test Generate tokens username"
            let userEmail = "test.generate_tokens@behide.com" |> Email.parse
            let accessToken, refreshToken, accessTokenHash, refreshTokenHash =
                BehideApi.JWT.generateTokens userId userName userEmail

            // Test claims
            let jwt = JwtSecurityToken(accessToken)
            let claims = jwt.Claims |> Seq.map (fun claim -> claim.Type, claim.Value)

            let audience = jwt.Audiences |> Seq.tryHead |> Expect.wantSome "JWT claims should contain audience"
            let issuer = jwt.Issuer
            let nameIdentifier = claims |> getClaim ClaimTypes.NameIdentifier
            let name = claims |> getClaim ClaimTypes.Name
            let email = claims |> getClaim ClaimTypes.Email

            Expect.equal "JWT issuer should not be that" "https://behide.netlify.app" issuer
            Expect.equal "JWT audience should not be that" "https://behide.netlify.app" audience
            Expect.equal "JWT name identifier should not be that" (userId |> UserId.rawString) nameIdentifier
            Expect.equal "JWT name should not be that" userName name
            Expect.equal "JWT email should not be that" (userEmail |> Email.raw) email

            // Test hashes
            let hasher = PasswordHasher()
            let accessTokenRes = hasher.VerifyHashedPassword("", accessTokenHash, accessToken)
            let refreshTokenRes = hasher.VerifyHashedPassword("", refreshTokenHash, refreshToken)

            Expect.notEqual "Access token should be valid" PasswordVerificationResult.Failed accessTokenRes
            Expect.notEqual "Access token should be valid" PasswordVerificationResult.Failed refreshTokenRes
        }

        testTask "Verify tokens" {
            let! user, (accessToken: string), (refreshToken: string) = Helpers.Auth.createUser()

            BehideApi.JWT.verifyUserTokens user accessToken refreshToken
            |> Expect.wantOk "Tokens should be approved"
        }
    ]

    testTask "Authorized user should be able to refresh his tokens" {
        let client = Helpers.getClient()
        let! _user, (accessToken: string), (refreshToken: string) = Helpers.Auth.createUser()

        // Refresh
        let! (response: DTO.Auth.RefreshToken.Response) = (accessToken, refreshToken) |> refreshTokens client

        // Refresh with wrong tokens
        do! (accessToken, refreshToken)
            |> refreshTokensReq
            |> Helpers.Http.send HttpStatusCode.Unauthorized client
            |> Task.map ignore

        // Re-refresh with correct tokens
        do! (response.accessToken, response.refreshToken)
            |> refreshTokens client
            |> Task.map ignore
    }
]