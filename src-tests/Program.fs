module BehideApi.Tests.Program

open Expecto

[<EntryPoint>]
let main args = runTestsInAssemblyWithCLIArgs [ JUnit_Summary "TestResults.xml" ] args
