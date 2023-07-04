namespace BehideApi.Types.DTO

open BehideApi.OpenAPI.Types

module Auth =
    module RefreshToken =
        let createResponse accessToken refreshToken : PostAuthRefreshToken_OK =
            { accessToken = accessToken
              refreshToken = refreshToken }