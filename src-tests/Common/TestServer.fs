module BehideApi.Tests.Common.TestServer

open Microsoft.AspNetCore
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.AspNetCore.TestHost
open Microsoft.AspNetCore.Authentication.Cookies
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Logging
open Microsoft.IdentityModel.Tokens

open Falco

open BehideApi
open BehideApi.Common


let configureServices (builder: WebHostBuilderContext) (services: IServiceCollection) =
    services
        .AddFalco()
        .AddAuthorization()
        .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(fun options ->
            options.LoginPath <- "/auth/sign-in"
            options.LogoutPath <- "/auth/sign-out"
        )
        .AddJwtBearer(fun options ->
            options.TokenValidationParameters <- new TokenValidationParameters(
                ClockSkew = System.TimeSpan.Zero,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = builder.Configuration["jwt:issuer"],
                ValidAudience = builder.Configuration["jwt:audience"],
                IssuerSigningKey = Config.Auth.JWT.securityKey
            )
        )
        .AddDiscord(fun options ->
            options.ClientId <- Config.Auth.Discord.clientId
            options.ClientSecret <- Config.Auth.Discord.clientSecret
            options.CallbackPath <- "/auth/signin-discord"
        )
        .AddGoogle(fun options ->
            options.ClientId <- Config.Auth.Google.clientId
            options.ClientSecret <- Config.Auth.Google.clientSecret
            options.CallbackPath <- "/auth/signin-google"
        )
    |> ignore

let configureApp (_: WebHostBuilderContext) (app: IApplicationBuilder) =
    app.UseAuthentication()
       .UseAuthorization()
       .UseCookiePolicy(CookiePolicyOptions(MinimumSameSitePolicy = Http.SameSiteMode.Lax))
       .UseFalcoExceptionHandler(Response.withStatusCode 500 >> Response.ofPlainText "Server Error")
       .UseFalco(Program.allEndpoints)
       |> ignore

let createTestServer () =
    WebHost
        .CreateDefaultBuilder()
        .ConfigureServices(configureServices)
        .Configure(configureApp)
        .ConfigureLogging(fun logging ->
            logging.AddFilter(function
                | LogLevel.Critical
                | LogLevel.Error
                | LogLevel.Warning -> true
                | _ -> false
            ) |> ignore
        )
    |> fun builder -> new TestServer(builder)