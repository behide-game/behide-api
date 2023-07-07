module BehideApi.Tests.Common.Helpers

open Expecto
open Expecto.Flip
open System.Net.Http
open System.Threading.Tasks
open Thoth.Json.Net
open FsToolkit.ErrorHandling


let getClient () =
    let testServer = TestServer.createTestServer()
    testServer.CreateClient()


module private Serialization =
    let decoder<'T> = Decode.Auto.generateDecoderCached<'T>()


module Http =
    let send expectedStatusCode (client: HttpClient) req = task {
        let! (response: HttpResponseMessage) = client.SendAsync req
        match expectedStatusCode = response.StatusCode with
        | false ->
            let! body = response.Content.ReadAsStringAsync()
            return failtestf
                "Unexpected status code.\nExpected: %s\nActual: %s\nBody: %s"
                (response.StatusCode |> string)
                (expectedStatusCode |> string)
                body
        | true -> return response
    }

    let parseResponse<'T> (taskResponse: Task<HttpResponseMessage>) =
        taskResponse
        |> Task.bind (fun res -> res.Content.ReadAsStringAsync())
        |> Task.map (Decode.fromString Serialization.decoder<'T>)


module Auth =
    open BehideApi
    open BehideApi.Types
    open BehideApi.Repository

    let createUser () =
        let userId = UserId.create()
        let userName = sprintf "test-user-%s" (System.Guid.NewGuid().ToString())
        let userEmail = userName |> sprintf "%s@behide.com" |> Email.parse

        let accessToken, refreshToken, accessTokenHash, refreshTokenHash =
            JWT.generateTokens userId userName userEmail

        let user: User = {
            Id = userId
            Name = userName
            AuthConnections = {
                NameIdentifier = "1"
                Email = userEmail
                Provider = AuthProvider.Discord
            } |> Array.singleton
            AccessTokenHash = accessTokenHash
            RefreshTokenHash = refreshTokenHash
        }

        task {
            do! user |> Database.Users.insert
            return user, accessToken, refreshToken
        }