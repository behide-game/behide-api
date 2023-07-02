namespace FsToolkit.ErrorHandling

open FsToolkit.ErrorHandling
open System.Threading.Tasks

module Result =
    let eitherId res = Result.either id id res
    let ofOption error = function Some value -> Ok value | None -> Error error

module TaskResult =
    let eitherId' taskResult = Task.bind Result.eitherId taskResult
    let eitherId (taskResult: Task<Result<Task, Task>>) : Task = task {
        let! res = taskResult
        return! res |> Result.eitherId
    }

    let ofOption error = Task.map (Result.ofOption error)