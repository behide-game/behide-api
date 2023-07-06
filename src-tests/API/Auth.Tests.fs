module BehideApi.Tests.API.Auth

open System
open System.Net
open System.Net.Http

open Expecto
open Expecto.Flip

open BehideApi.Types
open BehideApi.Tests.Common
open FsToolkit.ErrorHandling
open Microsoft.AspNetCore.Http.Extensions

// let refreshTokens client

[<Tests>]
let tests = testList "Auth" [
    testTask "Authorized user should be able to refresh his tokens" {
        let client = Helpers.getClient()
        let! (accessToken: string), (refreshToken: string) = Helpers.Auth.createUser()

        // Refresh
        let req = new HttpRequestMessage()
        let uri = UriBuilder("http://localhost:5000/auth/refresh-token")
        let query = new QueryBuilder()
        query.Add("access_token", accessToken)
        query.Add("refresh_token", refreshToken)

        uri.Query <- query.ToQueryString().ToString()
        req.RequestUri <- uri.Uri
        req.Method <- HttpMethod.Post

        let! (refreshedTokens: DTO.Auth.RefreshToken.Response) =
            req
            |> Helpers.Http.send HttpStatusCode.OK client
            |> Helpers.Http.parseResponse<DTO.Auth.RefreshToken.Response>
            |> Task.map (Expect.wantOk "Response should be parsable")

        // Refresh with wrong tokens
        let req = new HttpRequestMessage()
        let uri = UriBuilder("http://localhost:5000/auth/refresh-token")
        let query = new QueryBuilder()
        query.Add("access_token", accessToken)
        query.Add("refresh_token", refreshToken)

        uri.Query <- query.ToQueryString().ToString()
        req.RequestUri <- uri.Uri
        req.Method <- HttpMethod.Post

        let! _ = req |> Helpers.Http.send HttpStatusCode.Unauthorized client

        // Re-refresh with correct tokens
        let req = new HttpRequestMessage()
        let uri = UriBuilder("http://localhost:5000/auth/refresh-token")
        let query = new QueryBuilder()
        query.Add("access_token", refreshedTokens.accessToken)
        query.Add("refresh_token", refreshedTokens.refreshToken)

        uri.Query <- query.ToQueryString().ToString()
        req.RequestUri <- uri.Uri
        req.Method <- HttpMethod.Post

        let! (_: DTO.Auth.RefreshToken.Response) =
            req
            |> Helpers.Http.send HttpStatusCode.OK client
            |> Helpers.Http.parseResponse<DTO.Auth.RefreshToken.Response>
            |> Task.map (Expect.wantOk "Response should be parsable")

        ()
    }
]