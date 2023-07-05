module BehideApi.Repository.Database

open BehideApi.Types
open BehideApi.Common

open MongoDB.Bson
open MongoDB.Driver

open System.Threading.Tasks
open FsToolkit.ErrorHandling

let private connectionString = Config.Database.connectionString
let private mongo = connectionString |> MongoClient

let private databaseName = "Behide"
let private database = mongo.GetDatabase databaseName

module Users =
    open MongoDB.Driver
    let private collectionName = "users"
    let collection = database.GetCollection<User> collectionName

    let insert = collection.InsertOneAsync

    let findByUserId (userId: UserId) : Task<User list> =
        let filter = {| ``_id.UserId`` = userId |> UserId.rawBytes |}

        filter.ToBsonDocument()
        |> BsonDocumentFilterDefinition
        |> collection.FindAsync
        |> Task.bind (fun users -> users.ToListAsync())
        |> Task.map Seq.toList

    let findByUserEmail (email: Email) : Task<User list> =
        let filter = {| ``AuthConnections.Email.Email`` = (email |> Email.raw) |}

        filter.ToBsonDocument()
        |> BsonDocumentFilterDefinition
        |> collection.FindAsync
        |> Task.bind (fun users -> users.ToListAsync())
        |> Task.map Seq.toList

    let findByUserNameIdentifier (nameIdentifier: string) : Task<User list> =
        let filter = {| ``AuthConnections.NameIdentifier`` = nameIdentifier |}

        filter.ToBsonDocument()
        |> BsonDocumentFilterDefinition
        |> collection.FindAsync
        |> Task.bind (fun users -> users.ToListAsync())
        |> Task.map Seq.toList

    let updateTokenHashes userId (accessTokenHash: string) (refreshTokenHash: string) =
        let filter = {| ``_id.UserId`` = userId |> UserId.rawBytes |}
        let update = {| ``$set`` = {|
            AccessTokenHash = accessTokenHash
            RefreshTokenHash = refreshTokenHash
        |} |}

        collection.UpdateOneAsync(
            filter.ToBsonDocument(),
            update.ToBsonDocument()
        )
        |> TaskResult.simpleCatch (fun exn -> sprintf "Repository error, failed to update user tokens: %s" (exn.ToString()))
        |> TaskResult.map (fun x ->
            x.MatchedCount |> printfn "%A"
            x.ModifiedCount |> printfn "%A"
            x.UpsertedId |> printfn "%A"
        )