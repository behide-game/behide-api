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
        let filter = {| Id = userId |}

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