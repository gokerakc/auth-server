using AuthServer.App.Models;

namespace AuthServer.App.Services;

public interface IOpenIddictApplicationService
{
    Task Create(AuthServerClientRequest clientRequest);
}