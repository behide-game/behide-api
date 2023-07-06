module BehideApi.Tests.API.User

open Expecto
open BehideApi.Tests.Common
open System.Net
open System.Net.Http

[<Tests>]
let tests = testList "User" [
    testTask "Unauthorized user shouldn't be authorized" {
        let client = Helpers.getClient()

        do! new HttpRequestMessage(HttpMethod.Get, "/user")
            |> Helpers.Http.send HttpStatusCode.Unauthorized client
    }
]