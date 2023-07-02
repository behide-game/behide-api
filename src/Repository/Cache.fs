module BehideApi.Repository.Cache

open BehideApi.Types
open StackExchange.Redis
open FsToolkit.ErrorHandling

let config = "localhost,abortConnect=false,ssl=false"
let private redis = ConnectionMultiplexer.Connect config
let private db = redis.GetDatabase()

let private write (key: string) (value: string) =
    db.StringSetAsync(key, value)
    |> Task.map (function
        | true -> Ok ()
        | false -> Error (sprintf "Failed to set %s on redis database" key)
    )

let private read (key: string) =
    key
    |> db.StringGetAsync
    |> Task.map (fun value ->
        value.HasValue |> function
        | true -> value.ToString() |> Some
        | false -> None
    )


let getUserAccessToken (userId: UserId) =
    userId
    |> UserId.rawString
    |> sprintf "%s:access_token"
    |> read

let setUserAccessToken (userId: UserId) (accessToken: string) =
    write
        (userId |> UserId.rawString |> sprintf "%s:access_token")
        accessToken


let getUserRefreshToken (userId: UserId) =
    userId
    |> UserId.rawString
    |> sprintf "%s:refresh_token"
    |> read

let setUserRefreshToken (userId: UserId) (refreshToken: string) =
    write
        (userId |> UserId.rawString |> sprintf "%s:refresh_token")
        refreshToken