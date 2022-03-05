using System.Web;
using AuthServer.App.Models;
using AuthServer.App.Services;
using AuthServer.App.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.App.Controllers;

public class AccountController : Controller
{
    private readonly IUserService _userService;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IEmailService _emailService;
    private readonly ILogger<AccountController> _logger;

    public AccountController(IUserService userService, SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager, IEmailService emailService, ILogger<AccountController> logger)
    {
        _userService = userService;
        _signInManager = signInManager;
        _userManager = userManager;
        _emailService = emailService;
        _logger = logger;
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> Login(string? returnUrl)
    {
        var (token, userId) = GetCallbackParams(returnUrl);
        if (string.IsNullOrWhiteSpace(token) == false && string.IsNullOrWhiteSpace(userId) == false)
        {
            if (await ProcessLoginCallback(token, userId))
            {
                Redirect(returnUrl!);
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

            var loginRequest = new LoginRequest(model.Email ?? string.Empty, model.Password ?? string.Empty)
            {
                RedirectUri = query.Get("redirect_uri"),
                ClientId = query.Get("client_id"),
                CodeChallenge = query.Get("code_challenge"),
                CodeChallengeMethod = query.Get("code_challenge_method"),
                Scope = query.Get("scope"),
                State = query.Get("state"),
                Nonce = query.Get("nonce")
            };

            var loginUrl = await _userService.Login(HttpContext, loginRequest);

            if (string.IsNullOrEmpty(loginUrl))
            {
                model.Email = null;
                model.Password = null;

                return View(model);
            }

            return string.IsNullOrEmpty(model.ReturnUrl) ? RedirectToAction(nameof(Login)) : Redirect(loginUrl);
        }

        return View(model);
    }

    [HttpGet]
    public async Task<IActionResult> Logout()
    {
        await _userService.Logout();

        return RedirectToAction(nameof(Login));
    }
    
    [HttpGet]
    [AllowAnonymous]
    public Task<IActionResult> Register() =>Task.FromResult<IActionResult>(View());
    
    
    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (ModelState.IsValid == false)
        {
            return View(model);
        }

        var applicationUser = new ApplicationUser
        {
            UserName = model.Email,
            Email = model.Email,
            FirstName = model.FirstName,
            LastName = model.LastName
        };
        
        var result = await _userManager.CreateAsync(applicationUser, model.Password);

        if(!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.TryAddModelError(error.Code, error.Description);
            }
            return View(model);
        }
        await _userManager.AddToRoleAsync(applicationUser, UserRole.Visitor.ToString());

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(applicationUser);
        var confirmationLink = Url.Action(nameof(ConfirmEmail), "Account", new { token, email = applicationUser.Email }, Request.Scheme);
        
        _emailService.SendVerificationEmail(confirmationLink!);
        
        return RedirectToAction(nameof(SuccessRegistration));
    }
    
    [HttpGet]
    public async Task<IActionResult> ConfirmEmail(string token, string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
            return View("Error");
        
        var result = await _userManager.ConfirmEmailAsync(user, token);
        return View(result.Succeeded ? nameof(ConfirmEmail) : nameof(Error));
    }
    
    [HttpGet]
    public IActionResult SuccessRegistration()
    {
        return View();
    }
    
    [HttpGet]
    public IActionResult Error()
    {
        return View();
    }

    private static Tuple<string?, string?> GetCallbackParams(string? returnUrl)
    {
        if (returnUrl == null) return new Tuple<string?, string?>(null,  null);
        
        var uri = new Uri(new Uri("http://localhost"), returnUrl);
        var query = HttpUtility.ParseQueryString(uri.Query);

        var token = query.Get("token");
        var userId = query.Get("us");

        return new Tuple<string?, string?>(token, userId);
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
