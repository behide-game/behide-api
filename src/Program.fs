module BehideApi.Program

open BehideApi.Common
open NamelessInteractive.FSharp.MongoDB

open Falco.HostBuilder

open Microsoft.AspNetCore.Authentication.Cookies
open Microsoft.AspNetCore.Builder
open Microsoft.Extensions.DependencyInjection
open Microsoft.IdentityModel.Tokens


let allEndpoints = [
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
            app.UseCookiePolicy(CookiePolicyOptions(MinimumSameSitePolicy = Microsoft.AspNetCore.Http.SameSiteMode.Lax))
        )

        use_authorization
        use_authentication
        endpoints allEndpoints
    }

    0