﻿module BehideApi.Program

open BehideApi.Common
open NamelessInteractive.FSharp.MongoDB

open Falco
open Falco.Routing
open Falco.HostBuilder

open Microsoft.AspNetCore.Authentication.Cookies
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.DependencyInjection

let allEndpoints = [
    any "/" (Response.ofPlainText "It's alive!")
    yield! API.Authentication.endpoints
    yield! API.User.endpoints
]

[<EntryPoint>]
let main args =
    // Register MongoDB serializers
    SerializationProviderModule.Register()
    Conventions.ConventionsModule.Register()
    Serialization.SerializationProviderModule.Register()

    webHost args {
        host (fun builder -> builder.ConfigureServices(fun builder services ->
            services
                .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(fun options ->
                    options.LoginPath <- "/auth/sign-in"
                    options.LogoutPath <- "/auth/sign-out"
                )
                .AddJwtBearer(fun options ->
                    options.TokenValidationParameters <- Config.Auth.JWT.validationParameters
                )
                .AddDiscord("discord", fun options ->
                    options.ClientId <- Config.Auth.Discord.clientId
                    options.ClientSecret <- Config.Auth.Discord.clientSecret
                    options.CallbackPath <- "/auth/signin-discord"
                )
                .AddGoogle("google", fun options ->
                    options.ClientId <- Config.Auth.Google.clientId
                    options.ClientSecret <- Config.Auth.Google.clientSecret
                    options.CallbackPath <- "/auth/signin-google"
                )
                .AddMicrosoftAccount("microsoft", fun options ->
                    options.ClientId <- Config.Auth.Microsoft.clientId
                    options.ClientSecret <- Config.Auth.Microsoft.clientSecret
                    options.CallbackPath <- "/auth/signin-microsoft"
                )
            |> ignore
        ))

        use_middleware (fun app ->
            let forceHttpsHandler = System.Func<HttpContext, RequestDelegate, System.Threading.Tasks.Task>(fun ctx next ->
                ctx.Request.Scheme <- "https"
                next.Invoke ctx
            )

            app.UseCookiePolicy(CookiePolicyOptions(MinimumSameSitePolicy = SameSiteMode.Lax))
               .UseHttpsRedirection()
               .Use(forceHttpsHandler)
        )

        use_authorization
        use_authentication
        endpoints allEndpoints
    }

    0