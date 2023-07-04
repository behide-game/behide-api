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

module Tokens =
    let private collectionName = "tokens"
    let private collection = database.GetCollection<Auth.Token> collectionName

    let upsert (token: Auth.Token) =
        let filter = {| ``UserId.UserId`` = token.UserId |> UserId.rawBytes |}

        collection.ReplaceOneAsync(
            filter.ToBsonDocument() |> BsonDocumentFilterDefinition,
            token,
            ReplaceOptions(IsUpsert = true)
        )
        |> Task.map ignore
        |> TaskResult.simpleCatch (fun exn -> sprintf "Repository error, failed to upsert user tokens: %s" (exn.ToString()))

    let findByUserId (userId: UserId) : TaskResult<Auth.Token option, string> =
        let filter = {| ``UserId.UserId`` = userId |> UserId.rawBytes |}

        filter.ToBsonDocument()
        |> BsonDocumentFilterDefinition
        |> collection.FindAsync
        |> Task.bind (fun users -> users.FirstOrDefaultAsync())
        |> Task.map Option.ofNull
        |> TaskResult.simpleCatch (fun exn -> sprintf "Repository error, failed to find user tokens: %s" exn.Message)