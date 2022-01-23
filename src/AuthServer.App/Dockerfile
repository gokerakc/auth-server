FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["src/AuthServer.App/AuthServer.App.csproj", "AuthServer.App/"]
RUN dotnet restore "src/AuthServer.App/AuthServer.App.csproj"
COPY . .
WORKDIR "/src/AuthServer.App"
RUN dotnet build "AuthServer.App.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "AuthServer.App.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "AuthServer.App.dll"]
