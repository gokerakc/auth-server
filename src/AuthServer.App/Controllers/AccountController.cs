using System.Web;
using AuthServer.App.Models;
using AuthServer.App.Services;
using AuthServer.App.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.App.Controllers;

public class AccountController : Controller
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUserService _userService;
    private readonly ILogger<AccountController> _logger;

    public AccountController(IUserService userService, SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager, ILogger<AccountController> logger)
    {
        _userService = userService;
        _signInManager = signInManager;
        _userManager = userManager;
        _logger = logger;
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> Login(string returnUrl = "http://localhost:5000")
    {
        var (token, userId) = GetCallbackParams(returnUrl);
        if (string.IsNullOrWhiteSpace(token) == false && string.IsNullOrWhiteSpace(userId) == false)
        {
            if (await ProcessLoginCallback(token, userId))
            {
                Redirect(returnUrl);
            }
            else
            {
                ModelState.AddModelError("", "The sign-in link has expired, please request a new one");
            }
        }

        var viewModel = new LoginViewModel(string.Empty, string.Empty, returnUrl);
        return View(viewModel);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        ViewData["ReturnUrl"] = model.ReturnUrl;

        if (ModelState.IsValid)
        {
            var uri = new Uri(new Uri("http://localhost"), model.ReturnUrl);
            var query = HttpUtility.ParseQueryString(uri.Query);

            var loginRequest = new LoginRequest
            {
                Username = model.Username,
                RedirectUri = query.Get("redirect_uri"),
                ClientId = query.Get("client_id"),
                CodeChallenge = query.Get("code_challenge"),
                CodeChallengeMethod = query.Get("code_challenge_method"),
                Scope = query.Get("scope"),
                State = query.Get("state"),
                Nonce = query.Get("nonce")
            };

            var loginUrl = await _userService.Login(HttpContext, loginRequest);

            return Redirect(loginUrl);
        }

        return View(model);
    }

    [HttpGet]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync();

        return View("Login");
    }

    private static Tuple<string, string> GetCallbackParams(string returnUrl)
    {
        var uri = new Uri(new Uri("http://localhost"), returnUrl);
        var query = HttpUtility.ParseQueryString(uri.Query);

        var token = query.Get("token");
        var userId = query.Get("us");

        return new Tuple<string, string>(token, userId);
    }

    private async Task<bool> ProcessLoginCallback(string token, string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        var isValid =
            await _userManager.VerifyUserTokenAsync(user, TokenOptions.DefaultProvider, TokenPurposes.DefaultPurpose, token);
        if (isValid == false)
        {
            return false;
        }

        var result = await _userManager.UpdateSecurityStampAsync(user);
        if (result.Succeeded == false)
        {
            var errors = result.Errors.Select(x => $"{x.Code}: {x.Description}");
            var error = string.Join(',', errors);
            _logger.LogError("Failed to update user security stamp {}", error);
            throw new Exception("Failed to update user security stamp");
        }

        await _signInManager.SignInAsync(user, false);
        
        _logger.LogInformation("User {UserId} logged in", user.Id);
        if (user.EmailConfirmed == false)
        {
            user.EmailConfirmed = true;
            await _userManager.UpdateAsync(user);
        }

        return true;
    }
}
