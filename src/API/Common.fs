module BehideApi.API.Common

open System.Text
open Microsoft.AspNetCore.Http

let bodyJsonOptions =
    Json.JsonSerializerOptions(
        AllowTrailingCommas = true,
        PropertyNameCaseInsensitive = true
    )

module FsToolkit =
    module ErrorHandling =
        module TaskResult =
            open System.Threading.Tasks
            open FsToolkit.ErrorHandling

            let eitherId: Task<Result<Task, Task>> -> Task = Task.bind (Result.either id id >> Task.ofUnit) >> fun task -> task :> Task

module Auth =
    open Falco
    open Falco.Security
    open System
    open System.Threading.Tasks
    open System.Security.Claims
    open Microsoft.AspNetCore.Authentication.JwtBearer

    let requireAuth (handleOk: ClaimsPrincipal -> HttpHandler) (ctx: HttpContext) =
        let handleError (failure: Exception) : HttpHandler =
            Response.withStatusCode StatusCodes.Status401Unauthorized
            >> Response.ofPlainText (sprintf "Unauthorized: %s" failure.Message)

        task {
            let! res = Auth.authenticate JwtBearerDefaults.AuthenticationScheme ctx
            match res.Succeeded with
            | false -> return! handleError res.Failure ctx
            | true -> return! handleOk res.Principal ctx
        } :> Task