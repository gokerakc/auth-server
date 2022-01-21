FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["AuthServer.Api/AuthServer.Api.csproj", "AuthServer.Api/"]
RUN dotnet restore "AuthServer.Api/AuthServer.Api.csproj"
COPY . .
WORKDIR "/src/AuthServer.Api"
RUN dotnet build "AuthServer.Api.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "AuthServer.Api.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "AuthServer.Api.dll"]
