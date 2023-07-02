module BehideApi.Tests.Program

open Expecto
open BehideApi.Tests.Common
open System.Net.Http
open System.Net

[<Tests>]
let allTests =
    testTask "test" {
        let testServer = TestServer.createTestServer()
        let client = testServer.CreateClient()

        let request = new HttpRequestMessage(HttpMethod.Get, "/user")
        let! (response: HttpResponseMessage) = client.SendAsync request

        Expect.equal response.StatusCode HttpStatusCode.Unauthorized "Should be unauthorized"
    }

[<EntryPoint>]
let main args =
    runTestsInAssemblyWithCLIArgs [ JUnit_Summary "TestResults.xml" ] args
