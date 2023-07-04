module BehideApi.JWT

open BehideApi.Types
open BehideApi.Common
open BehideApi.Repository

open System
open System.Text
open System.IdentityModel.Tokens.Jwt
open System.Security.Claims
open Microsoft.IdentityModel.Tokens
open FsToolkit.ErrorHandling


// JWT Generation
let tokenDuration = TimeSpan.FromDays 1

let securityKey =
    Config.Auth.JWT.signingKey
    |> Encoding.UTF8.GetBytes
    |> SymmetricSecurityKey

let credentials = SigningCredentials(
    securityKey,
    SecurityAlgorithms.HmacSha256
)

let createJwtToken claims =
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
    let userId = user.Id |> UserId.rawString
    let email = user.AuthConnections[0].Email |> Email.raw

    [ ClaimTypes.NameIdentifier, userId
      ClaimTypes.Name, user.Name
      ClaimTypes.Email, email ]
    |> Seq.map Claim
    |> createJwtToken


// Repository
let setUserTokens user accessToken refreshToken =
    let token: Auth.Token =
        { UserId = user.Id
          AccessToken = accessToken
          RefreshToken = refreshToken }

    token |> Database.Tokens.upsert

let getUserTokens (user: User) = user.Id |> Database.Tokens.findByUserId


// JWT Generation + Repository
let generateTokensForUser user = taskResult {
    let jwt = createJwtTokenForUser user
    let refreshToken = Guid.NewGuid().ToString()

    do! setUserTokens user jwt refreshToken
    return (jwt, refreshToken)
}

let refreshTokenForUser user accessToken refreshToken = taskResult {
    let! tokens = getUserTokens user |> TaskResult.bindRequireSome "Failed to retrieve user tokens"

    do! accessToken = tokens.AccessToken |> Result.requireTrue "Invalid access token"
    do! refreshToken = tokens.RefreshToken |> Result.requireTrue "Invalid refresh token"

    return! generateTokensForUser user
}