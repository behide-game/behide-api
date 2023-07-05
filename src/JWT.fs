module BehideApi.JWT

open BehideApi.Types
open BehideApi.Common
open BehideApi.Repository
module Config = Config.Auth.JWT

open System
open System.IdentityModel.Tokens.Jwt
open System.Security.Claims
open Microsoft.IdentityModel.Tokens
open FsToolkit.ErrorHandling

let private credentials = SigningCredentials(
    Config.securityKey,
    SecurityAlgorithms.HmacSha256
)

let private createJwtToken claims =
    JwtSecurityToken(
        issuer = "https://behide.netlify.app",
        audience = "https://behide.netlify.app",
        claims = claims,
        notBefore = DateTime.Now,
        expires = DateTime.Now + Config.tokenDuration,
        signingCredentials = credentials
    )
    |> JwtSecurityTokenHandler().WriteToken

let private createJwtUserClaims userId userName userEmail =
    let userId = userId |> UserId.rawString
    let email = userEmail |> Email.raw

    [ ClaimTypes.NameIdentifier, userId
      ClaimTypes.Name, userName
      ClaimTypes.Email, email ]
    |> Seq.map Claim


let private hashToken user token = Microsoft.AspNetCore.Identity.PasswordHasher().HashPassword(user, token)


// Public
let generateTokens userId userName userEmail =
    let accessToken =
        (userId, userName, userEmail)
        |||> createJwtUserClaims
        |> createJwtToken

    let refreshToken = Guid.NewGuid().ToString()

    let (accessTokenHash, refreshTokenHash) =
        accessToken |> hashToken (userId, userName, userEmail),
        refreshToken |> hashToken (userId, userName, userEmail)

    accessToken, refreshToken, accessTokenHash, refreshTokenHash


let verifyUserTokens user accessToken refreshToken = result {
    let passwordHasher = Microsoft.AspNetCore.Identity.PasswordHasher()

    let! _accessTokenMatch =
        passwordHasher.VerifyHashedPassword(user, user.AccessTokenHash, accessToken)
        |> function
            | Microsoft.AspNetCore.Identity.PasswordVerificationResult.Failed -> false
            | _ -> true
        |> Result.requireTrue "Invalid access token"

    let! _refreshTokenMatch =
        passwordHasher.VerifyHashedPassword(user, user.RefreshTokenHash, refreshToken)
        |> function
            | Microsoft.AspNetCore.Identity.PasswordVerificationResult.Failed -> false
            | _ -> true
        |> Result.requireTrue "Invalid refresh token"

    ()
}