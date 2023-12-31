module BehideApi.Tests.Common.Helpers

open Expecto
open Expecto.Flip
open System.Net.Http
open System.Threading.Tasks
open Thoth.Json.Net
open FsToolkit.ErrorHandling

open BehideApi
open BehideApi.Types
open BehideApi.Repository


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
                (expectedStatusCode |> string)
                (response.StatusCode |> string)
                body
        | true -> return response
    }

    let parseResponse<'T> (taskResponse: Task<HttpResponseMessage>) =
        taskResponse
        |> Task.bind (fun res -> res.Content.ReadAsStringAsync())
        |> Task.map (Decode.fromString Serialization.decoder<'T>)


module User =
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
                NameIdentifier = System.Guid.NewGuid().ToString()
                Email = userEmail
                Provider = AuthProvider.Discord
            } |> Array.singleton
            AccessTokenHash = accessTokenHash
            RefreshTokenHash = refreshTokenHash
        }

        user, accessToken, refreshToken

    let createUserWithAuthConnections authConnections =
        let rawUser, accessToken, refreshToken = createUser()
        { rawUser with AuthConnections = authConnections}, accessToken, refreshToken

    let createAuthConnection provider =
        { NameIdentifier = System.Guid.NewGuid().ToString()
          Email = System.Guid.NewGuid().ToString() |> sprintf "%s@behide.com" |> Email.parse
          Provider = provider }

    let createAuthConnectionForAllProviders () =
        [| AuthProvider.Discord
           AuthProvider.Google
           AuthProvider.Microsoft |]
        |> Array.map createAuthConnection


module Database =
    let addUser (user, accessToken, refreshToken) =
        task {
            do! user |> Database.Users.insert
            return user, accessToken, refreshToken
        }

    let populateWithUsers () =
        task {
            let max = 20.
            let min = 5.
            let userCount = System.Random().NextDouble() * (max - min) + min |> int
            let userList = List.init userCount (ignore >> User.createUser)

            for user in userList do
                do! user |> addUser |> Task.map ignore

            let randomUserIndex =
                System.Random().NextDouble()
                * (float userCount)
                |> System.Math.Floor
                |> int

            return userList |> List.item randomUserIndex
        }