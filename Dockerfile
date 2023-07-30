FROM mcr.microsoft.com/dotnet/sdk:7.0 as build-env

# Restore
COPY behide-api.sln .
COPY .config .
COPY .paket .
COPY paket.dependencies .
COPY paket.lock .
COPY src/BehideApi.fsproj src/BehideApi.fsproj

RUN dotnet tool restore
RUN dotnet paket restore
RUN dotnet restore src

# Build
COPY src/ src/

COPY hawaii.json .
COPY openapi.json .
RUN dotnet hawaii

RUN dotnet publish src -c Release -o /publish

# --- Runtime ---
FROM mcr.microsoft.com/dotnet/aspnet:7.0 as runtime
WORKDIR /publish
COPY --from=build-env /publish .
EXPOSE 80

# ENV
ENV AUTH_DISCORD_CLIENT_SECRET=_
ENV AUTH_DISCORD_CLIENT_ID=_
ENV AUTH_GOOGLE_CLIENT_ID=_
ENV AUTH_GOOGLE_CLIENT_SECRET=_
ENV AUTH_MICROSOFT_CLIENT_ID=_
ENV AUTH_MICROSOFT_CLIENT_SECRET=_
ENV JWT_SIGNING_KEY=_
ENV MONGODB_CONNECTION_STRING=_

ENTRYPOINT ["dotnet", "BehideApi.dll"]