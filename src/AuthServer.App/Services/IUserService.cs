using AuthServer.App.Models;

namespace AuthServer.App.Services;

public interface IUserService
{
    Task<string> Login(HttpContext httpContext, LoginRequest loginRequest);
    
    Task Logout();
}

