module BehideApi.API.Common

open BehideApi.Types
open BehideApi.Repository

open System.Text
open System.Threading.Tasks
open Microsoft.AspNetCore.Http
open FsToolkit.ErrorHandling

let jsonOptions =
    Json.JsonSerializerOptions(
        AllowTrailingCommas = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = Json.JsonNamingPolicy.CamelCase
    )

module Handler =
    let fromTRHandler (handler: HttpContext -> TaskResult<Task, (HttpContext -> Task)>) ctx =
        task {
            match! handler ctx with
            | Ok task -> return! task
            | Error handler -> return! handler ctx
        } :> Task

module Auth =
    open Falco
    open Falco.Helpers
    open Falco.Security
    open System
    open System.Security.Claims
    open Microsoft.AspNetCore.Authentication.JwtBearer

    let requireAuth (handleOk: HttpHandler) (ctx: HttpContext) =
        let handleError (failure: Exception) : HttpHandler =
            Response.withStatusCode StatusCodes.Status401Unauthorized
            >> Response.ofPlainText (sprintf "Unauthorized: %s" failure.Message)

        task {
            let! res = Auth.authenticate JwtBearerDefaults.AuthenticationScheme ctx
            match res.Succeeded with
            | false -> return! handleError res.Failure ctx
            | true ->
                ctx.User <- res.Principal
                return! handleOk ctx
        } :> Task

    let getBehideUser (ctx: HttpContext) =
        taskResult {
            let parseUserId =
                UserId.tryParse
                >> Result.ofOption (Response.unauthorized "Unauthorized, failed to parse name identifier")

            let! userId =
                ctx
                |> Auth.getClaimValue ClaimTypes.NameIdentifier
                |> Result.ofOption (Response.unauthorized "Unauthorized")
                |> Result.bind parseUserId

            let! user =
                userId
                |> Database.Users.findByUserId
                |> Task.map List.tryHead
                |> TaskResult.ofOption (Response.notFound "Cannot find user")

            return user
        }