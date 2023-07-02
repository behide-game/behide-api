module BehideApi.Tests.Common.Helpers

open Expecto.Flip
open System.Net.Http

let getClient () =
    let testServer = TestServer.createTestServer()
    testServer.CreateClient()

let send expectedStatusCode (client: HttpClient) req = task {
    let! (response: HttpResponseMessage) = client.SendAsync req
    Expect.equal "Should be unauthorized" response.StatusCode expectedStatusCode

    return response
}
