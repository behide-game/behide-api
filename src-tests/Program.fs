module BehideApi.Tests.Program

open Expecto
open BehideApi
open BehideApi.Repository
open MongoDB.Bson
open NamelessInteractive.FSharp.MongoDB

let cleanDatabase () =
    let filter = {||}.ToBsonDocument()
    Database.Users.collection.DeleteManyAsync(filter).Wait()

[<EntryPoint>]
let main args =
    // Register MongoDB serializers
    SerializationProviderModule.Register()
    Conventions.ConventionsModule.Register()
    Serialization.SerializationProviderModule.Register()

    printfn "Cleaning database ..."
    cleanDatabase()
    printfn ""

    runTestsInAssemblyWithCLIArgs [ JUnit_Summary "TestResults.xml" ] args