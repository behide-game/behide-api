module BehideApi.API.Common

open BehideApi.Types
open BehideApi.Repository

open System
open System.Text
open System.Web
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


module Request =
    let private parseRedirectUri name rawUriOpt = result {
        let! rawUri =
            rawUriOpt
            |> Option.map HttpUtility.UrlDecode
            |> Result.ofOption (name + " not provided")

        try
            return! UriBuilder(rawUri).Uri.AbsoluteUri |> Ok
        with _ ->
            return! Error (sprintf "provided %s is not valid" name)
    }

    module Route =
        let getRedirectUri name ctx =
            let route = Falco.Request.getRoute ctx

            route.TryGetString name
            |> parseRedirectUri name

    module Query =
        let getRedirectUri name ctx =
            let query = Falco.Request.getQuery ctx

            query.TryGetString name
            |> parseRedirectUri name

module Auth =
    open Falco
    open Falco.Helpers
    open Falco.Security
    open System.Security.Claims
    open Microsoft.AspNetCore.Authentication.JwtBearer

    let requireAuth (handleOk: HttpHandler) (ctx: HttpContext) =
        let handleError (failure: exn option) : HttpHandler =
            let message =
                failure
                |> Option.map (fun f -> f.Message)
                |> Option.map (sprintf "Unauthorized: %s")
                |> Option.defaultValue "Unauthorized"

            Response.withStatusCode StatusCodes.Status401Unauthorized
            >> Response.ofPlainText message

        task {
            let! res = Auth.authenticate JwtBearerDefaults.AuthenticationScheme ctx
            match res.Succeeded with
            | false -> return! handleError (res.Failure |> Option.ofNull) ctx
            | true ->
                ctx.User <- res.Principal
                return! handleOk ctx
        } :> Task

    let getBehideUserId (ctx: HttpContext) =
        result {
            let parseUserId =
                UserId.tryParse
                >> Result.ofOption (Response.unauthorized "Unauthorized, failed to parse name identifier")

            let! userId =
                ctx
                |> Auth.getClaimValue ClaimTypes.NameIdentifier
                |> Result.ofOption (Response.unauthorized "Unauthorized")
                |> Result.bind parseUserId

            return userId
        }

    let getBehideUser (ctx: HttpContext) =
        taskResult {
            let! userId = getBehideUserId ctx

            let! user =
                userId
                |> Database.Users.findByUserId
                |> TaskResult.ofOption (Response.notFound "Cannot find user")

            return user
        }