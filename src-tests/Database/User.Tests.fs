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

            Expect.equal "Database user should equal original user" user dbUser
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
        }

        testTask "Find a user by auth name identifier" {
            let! (user: User), _, _ = Helpers.Database.populateWithUsers()

            do! user.AuthConnections[0].NameIdentifier
                |> Database.Users.findAllByUserNameIdentifier
                |> Task.map (Expect.sequenceEqual "Should find user" [ user ])

            do! user.AuthConnections[0].NameIdentifier
                |> Database.Users.findByUserNameIdentifier
                |> Task.map (Expect.isSome "Should find user")
        }

        testTask "Update user token hashes" {
            let! (user: User), _, _ = Helpers.User.createUser() |> Helpers.Database.addUser

            do! Database.Users.updateTokenHashes user.Id "newAccessTokenHash" "newRefreshTokenHash"
                |> Task.map (Expect.isOk "User should be updated successfully")

            let! (dbUser: User) =
                user.Id
                |> Database.Users.findByUserId
                |> Task.map (Expect.wantSome "Should find user")

            Expect.equal "AccessTokenHash property should be updated" "newAccessTokenHash" dbUser.AccessTokenHash
            Expect.equal "RefreshTokenHash property should be updated" "newRefreshTokenHash" dbUser.RefreshTokenHash
        }

        testTask "Get user auth connections" {

            // Generate user
            let authConnections = Helpers.User.createAuthConnectionForAllProviders()

            let! user, _, _ =
                authConnections
                |> Helpers.User.createUserWithAuthConnections
                |> Helpers.Database.addUser

            // Test
            let! dbAuthConnections =
                user.Id
                |> Database.Users.getAuthConnections
                |> Task.map (Expect.wantOk "Should be able to retrieve user auth connections")

            (authConnections, dbAuthConnections)
            ||> Expect.sequenceEqual "Auth connections should equal"
        }

        testTask "Add user auth connections" {

            // Generate user
            let baseAuthConnection = AuthProvider.Discord |> Helpers.User.createAuthConnection
            let! user, _, _ =
                baseAuthConnection
                |> Array.singleton
                |> Helpers.User.createUserWithAuthConnections
                |> Helpers.Database.addUser

            // Update user
            let newAuthConnection = Helpers.User.createAuthConnection AuthProvider.Google

            do! newAuthConnection
                |> Database.Users.addAuthConnection user.Id
                |> Task.map (Expect.wantOk "Should be able to add auth connection to a user")

            // Update user a 2nd time
            let newAuthConnection2 = Helpers.User.createAuthConnection AuthProvider.Microsoft

            do! newAuthConnection2
                |> Database.Users.addAuthConnection user.Id
                |> Task.map (Expect.wantOk "Should be able to add auth connection to a user")

            // Check
            let! dbAuthConnections =
                user.Id
                |> Database.Users.getAuthConnections
                |> Task.map (Expect.wantOk "Should be able to retrieve user auth connections")

            Expect.sequenceEqual "Auth connections should equal"
                [| baseAuthConnection; newAuthConnection; newAuthConnection2 |]
                dbAuthConnections
        }
    ]
]