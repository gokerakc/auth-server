using Microsoft.AspNetCore.Identity;

namespace AuthServer.App.Models;

public class ApplicationUser : IdentityUser
{
    public string? Title { get; set; }

    public string? FirstName { get; set; }

    public string? LastName { get; set; }

    [ProtectedPersonalData]
    public DateTime? DateOfBirth { get; set; }
}