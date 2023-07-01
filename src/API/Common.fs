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