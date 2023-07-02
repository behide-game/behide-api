module Falco.Helpers

open Falco
open System.Net
open System.Threading.Tasks
open Microsoft.AspNetCore.Http
open FsToolkit.ErrorHandling

module Response =
    let handleError (errorStatusCode: HttpStatusCode) (task: Task<_>) : Task<Result<_, HttpHandler>> =
        task
        |> Task.catch
        |> Task.map (function
            | Choice1Of2 x -> Ok x
            | Choice2Of2 exn ->
                Error (fun (ctx: HttpContext) ->
                    ctx
                    |> Response.withStatusCode (errorStatusCode |> int)
                    |> Response.ofPlainText exn.Message
                )
        )

    let handleError' (errorStatusCode: HttpStatusCode) (task: Task) =
        task |> Task.ofUnit |> handleError errorStatusCode

    let internalServerError error : HttpHandler =
        Response.withStatusCode (HttpStatusCode.InternalServerError |> int)
        >> Response.ofPlainText error

    let badRequest error : HttpHandler =
        Response.withStatusCode (HttpStatusCode.BadRequest |> int)
        >> Response.ofPlainText error

    let unauthorized error : HttpHandler =
        Response.withStatusCode (HttpStatusCode.Unauthorized |> int)
        >> Response.ofPlainText error

    let forbidden error : HttpHandler =
        Response.withStatusCode (HttpStatusCode.Forbidden |> int)
        >> Response.ofPlainText error

    let notFound error : HttpHandler =
        Response.withStatusCode (HttpStatusCode.NotFound |> int)
        >> Response.ofPlainText error