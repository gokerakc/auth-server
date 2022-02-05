using System.Web;
using AuthServer.App.Models;
using Microsoft.AspNetCore.Identity;

namespace AuthServer.App.Services;

public class UserService : IUserService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<UserService> _logger;

    public UserService(
        UserManager<ApplicationUser> userManager, 
        SignInManager<ApplicationUser> signInManager,
        ILogger<UserService> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
    }

    public async Task<string> Login(HttpContext httpContext, LoginRequest loginRequest)
    {
        var user = await _userManager.FindByEmailAsync(loginRequest.Email);
        if (user == null)
        {
            _logger.LogInformation("User record does not exist");
            return string.Empty;
        }

        var signInResult = await _signInManager.PasswordSignInAsync(user, loginRequest.Password, isPersistent: true, lockoutOnFailure: false);

        if (signInResult.Succeeded == false)
        {
            _logger.LogInformation("Wrong password");
            return string.Empty;
        }

        var token =
            await _userManager.GenerateUserTokenAsync(user, TokenOptions.DefaultProvider,
                TokenPurposes.DefaultPurpose);

        var spaceSeparatedScopes = loginRequest.Scope;
            
        var baseUrl = $"{httpContext.Request.Scheme}://{httpContext.Request.Host}/oauth/connect/authorize?";
        var queryParams =
            $"scope={spaceSeparatedScopes}&response_type=code&client_id={loginRequest.ClientId ?? ""}" +
            $"&token={HttpUtility.UrlEncode(token)}&us={HttpUtility.UrlEncode(user.Id)}" +
            $"&redirect_uri={HttpUtility.UrlEncode(loginRequest.RedirectUri) ?? ""}" +
            $"&code_challenge={loginRequest.CodeChallenge ?? ""}" +
            $"&code_challenge_method={loginRequest.CodeChallengeMethod ?? ""}" +
            $"&state={loginRequest.State ?? ""}&nonce={loginRequest.Nonce ?? ""}";

        return $"{baseUrl}{queryParams}";
    }

    public async Task Logout()
    {
        await _signInManager.SignOutAsync();
    }
}