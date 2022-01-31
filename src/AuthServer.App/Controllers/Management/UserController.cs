using System.Net;
using AuthServer.App.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.JsonPatch;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.App.Controllers.Management;

[Route("mgmt/[controller]")]
[ApiController]
// [Authorize(Policy = Constants.ElevatedPrivilegesPolicyName)]
// [ApiVersion("1")]
// [Produces(MediaTypes.User)]
public class UserController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<UserController> _logger;

    public UserController(UserManager<ApplicationUser> userManager, ILogger<UserController> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    [HttpGet]
    [ProducesResponseType((int) HttpStatusCode.OK)]
    [ProducesResponseType((int) HttpStatusCode.Unauthorized)]
    public async Task<IActionResult> GetAll()
    {
        var users = await _userManager.Users.ToListAsync();
        var results = new List<AuthServerUser>();
        foreach (var user in users)
        {
            var roles = await _userManager.GetRolesAsync(user);
            results.Add(Map(user, roles));
        }
            
        return Ok(results);
    }

    [HttpGet("{userId}")]
    [ProducesResponseType((int) HttpStatusCode.OK)]
    [ProducesResponseType((int) HttpStatusCode.NotFound)]
    [ProducesResponseType((int) HttpStatusCode.Unauthorized)]
    public async Task<IActionResult> Get(Guid userId)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
        {
            return new NotFoundResult();
        }

        var roles = await _userManager.GetRolesAsync(user);
        return Ok(Map(user, roles));
    }

    [HttpPost]
    [ProducesResponseType((int) HttpStatusCode.Created)]
    [ProducesResponseType((int) HttpStatusCode.Conflict)]
    [ProducesResponseType((int) HttpStatusCode.BadRequest)]
    [ProducesResponseType((int) HttpStatusCode.Unauthorized)]
    public async Task<IActionResult> Create(AuthServerUser user)
    {
        var applicationUser = Map(user);
        var result = await _userManager.CreateAsync(applicationUser, user.Password);
        if (!result.Succeeded)
        {
            HandleErrors(result.Errors);
            return ValidationProblem();
        }

        result = await _userManager.AddToRolesAsync(applicationUser, user.Roles.Select(x => x.ToString()));
        if (!result.Succeeded)
        {
            HandleErrors(result.Errors);
            return ValidationProblem();
        }

        _logger.LogInformation("User with email '{Email}' created", user.Email);

        var createdUser = await _userManager.FindByEmailAsync(user.Email);
        var userRoles = await _userManager.GetRolesAsync(createdUser);

        return Created(Url.ActionLink(nameof(Get), "Users",
            new { userId = createdUser.Id }) ?? string.Empty, Map(createdUser, userRoles));
    }

    [HttpPatch("{userId}")]
    [ProducesResponseType((int) HttpStatusCode.OK)]
    [ProducesResponseType((int) HttpStatusCode.BadRequest)]
    [ProducesResponseType((int) HttpStatusCode.Unauthorized)]
    public async Task<IActionResult> Patch(string userId,
        [FromBody] JsonPatchDocument<AuthServerUser> authServerUserPatch)
    {
        var applicationUser = await _userManager.FindByIdAsync(userId);
        if (applicationUser == null)
        {
            return new NotFoundResult();
        }
        var userRoles = await _userManager.GetRolesAsync(applicationUser);

        var authServerUser = Map(applicationUser, userRoles);
        authServerUserPatch.ApplyTo(authServerUser);

        applicationUser.Title = authServerUser.Title;
        applicationUser.FirstName = authServerUser.FirstName;
        applicationUser.LastName = authServerUser.LastName;

        var result = await _userManager.UpdateAsync(applicationUser);
        if (!result.Succeeded)
        {
            HandleErrors(result.Errors);
            return ValidationProblem();
        }

        await _userManager.RemoveFromRolesAsync(applicationUser, userRoles);
        result = await _userManager.AddToRolesAsync(applicationUser, authServerUser.Roles.Select(x => x.ToString()));
        if (!result.Succeeded)
        {
            HandleErrors(result.Errors);
            return ValidationProblem();
        }

        return Ok(authServerUser);
    }

    [HttpDelete("{userId}")]
    [ProducesResponseType((int) HttpStatusCode.NoContent)]
    [ProducesResponseType((int) HttpStatusCode.NotFound)]
    [ProducesResponseType((int) HttpStatusCode.Unauthorized)]
    public async Task<IActionResult> Delete(Guid userId)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
        {
            return new NotFoundResult();
        }

        var result = await _userManager.DeleteAsync(user);
        if (result.Succeeded == false)
        {
            HandleErrors(result.Errors);
            return ValidationProblem();
        }

        _logger.LogInformation("User with email '{Email}' deleted", user.Email);

        return NoContent();
    }

    private void HandleErrors(IEnumerable<IdentityError> identityErrors)
    {
        var errors = identityErrors
            .Select(x => $"{x.Code}: {x.Description}")
            .ToList();

        foreach (var error in errors)
        {
            ModelState.AddModelError("user", error);
        }

        _logger.LogError("Failed to create user: {Error}", string.Join(", ", errors));
    }

    private static AuthServerUser Map(ApplicationUser user, IList<string> roles) =>
        new AuthServerUser
        {
            Id = new Guid(user.Id),
            Email = user.Email,
            Title = user.Title,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Roles = roles.Select(x => (UserRole)Enum.Parse(typeof(UserRole), x)).ToArray()
        };

    private static ApplicationUser Map(AuthServerUser user) =>
        new ApplicationUser
        {
            Id = Guid.NewGuid().ToString(),
            Email = user.Email,
            UserName = user.Email,
            Title = user.Title,
            FirstName = user.FirstName,
            LastName = user.LastName
        };
}