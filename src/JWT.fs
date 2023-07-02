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


let generateTokensForUser user = taskResult {
    let jwt = createJwtTokenForUser user
    let refreshToken = Guid.NewGuid().ToString()

    do! Cache.setUserAccessToken user.Id jwt
    do! Cache.setUserRefreshToken user.Id refreshToken

    return (jwt, refreshToken)
}

let refreshTokenForUser user accessToken refreshToken = taskResult {
    let! dbAccessToken = Cache.getUserAccessToken user.Id |> TaskResult.ofOption "Failed to retrieve access token"
    let! dbRefreshToken = Cache.getUserRefreshToken user.Id |> TaskResult.ofOption "Failed to retrieve refresh token"

    do! accessToken = dbAccessToken |> Result.requireTrue "Invalid access token"
    do! refreshToken = dbRefreshToken |> Result.requireTrue "Invalid refresh token"

    return! generateTokensForUser user
}