module BehideApi.Tests.API.Database

open Expecto
open Expecto.Flip
open BehideApi.Types
open BehideApi.Repository
open BehideApi.Tests.Common

open FsToolkit.ErrorHandling

[<Tests>]
let tests = testList "Database" [
    testList "Users" [
        testTask "Create a user and find a user by id" {
            let! user, _, _ = Helpers.Database.populateWithUsers()

            let! dbUser =
                user.Id
                |> Database.Users.findByUserId
                |> Task.map (Expect.wantSome "Should find user")

            (user, dbUser)
            ||> Expect.equal "Database user should equal original user"
        }

        testTask "Find a inexistant user" {
            let! _ = Helpers.Database.populateWithUsers()

            do! UserId.create()
                |> Database.Users.findByUserId
                |> Task.map (Expect.isNone "Should not find user")
        }

        testTask "Find a user by email" {
            let! (user: User), _, _ = Helpers.Database.populateWithUsers()

            do! user.AuthConnections[0].Email
                |> Database.Users.findAllByUserEmail
                |> Task.map (Expect.sequenceEqual "Should find user" [ user ])
                |> Task.map ignore
        }

        testTask "Find a user by auth name identifier" {
            let! (user: User), _, _ = Helpers.Database.populateWithUsers()

            do! user.AuthConnections[0].NameIdentifier
                |> Database.Users.findAllByUserNameIdentifier
                |> Task.map (Expect.sequenceEqual "Should find user" [ user ])
                |> Task.map ignore

            do! user.AuthConnections[0].NameIdentifier
                |> Database.Users.findByUserNameIdentifier
                |> Task.map (Expect.wantSome "Should find user")
                |> Task.map ignore
        }
    ]
]