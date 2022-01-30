using System.Security.Claims;
using AuthServer.App.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace AuthServer.App.Controllers;

public class AuthorizationController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;

    public AuthorizationController(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    [HttpPost("~/connect/token"), Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        ClaimsPrincipal claimsPrincipal;
        if (request.IsClientCredentialsGrantType())
        {
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // Subject (sub) is a required field, we use the client id as the subject identifier here.
            identity.AddClaim(OpenIddictConstants.Claims.Subject,
                request.ClientId ?? throw new InvalidOperationException());

            claimsPrincipal = new ClaimsPrincipal(identity);

            claimsPrincipal.SetScopes(request.GetScopes());
        }
        else if (request.IsAuthorizationCodeGrantType())
        {
            // Retrieve the claims principal stored in the authorization code
            claimsPrincipal =
                (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme))
                .Principal ?? throw new InvalidOperationException();
        }
        else
        {
            throw new InvalidOperationException("The specified grant type is not supported.");
        }

        return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var parameters = request.GetParameters();
        var userId = parameters.ContainsKey("us") ? parameters["us"].ToString() : default;
        var user = string.IsNullOrEmpty(userId) ? null : await _userManager.FindByIdAsync(userId);

        var token = parameters.ContainsKey("token") ? parameters["token"].ToString() : default;

        var isValid = user != null
                      && !string.IsNullOrEmpty(token)
                      && await _userManager.VerifyUserTokenAsync(user, TokenOptions.DefaultProvider, TokenPurposes.DefaultPurpose, token);

        if (isValid == false)
        {
            return Challenge(
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                        Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                });
        }

        var roles = await _userManager.GetRolesAsync(user!);

        var claims = roles
            .Select(role =>
                new Claim(OpenIddictConstants.Claims.Role, role).SetDestinations(OpenIddictConstants.Destinations
                    .IdentityToken))
            .ToList();

        claims.Add(new Claim(OpenIddictConstants.Claims.Subject, user!.Id));

        var claimsIdentity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        // Set requested scopes (this is not done automatically)
        claimsPrincipal.SetScopes(request.GetScopes());

        // Signing in with the OpenIddict authentication scheme trigger OpenIddict to issue a code (which can be exchanged for an access token)
        return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}