using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace AuthServer.App.Models;

public class AuthServerUser
{
    public AuthServerUser(Guid id, string email, string firstName, string lastName, string title, UserRole[] roles)
    {
        Id = id;
        Email = email;
        Roles = roles;
        Title = title;
        FirstName = firstName;
        LastName = lastName;
    }

    public Guid Id { get; set; }
    
    [Required(ErrorMessage = "Password is required")]
    [StringLength(255, ErrorMessage = "Must be between 5 and 255 characters", MinimumLength = 5)]
    [DataType(DataType.Password)]
    public string? Password { get; set; }

    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [MinLength(2, ErrorMessage = "Must be at least {1} characters")]
    [MaxLength(50, ErrorMessage = "Must be less than {1} characters")]
    public string Title { get; set; }

    [Required]
    [MinLength(2, ErrorMessage = "Must be at least {1} characters")]
    [MaxLength(50, ErrorMessage = "Must be less than {1} characters")]
    public string FirstName { get; set; }

    [Required]
    [MinLength(2, ErrorMessage = "Must be at least {1} characters")]
    [MaxLength(50, ErrorMessage = "Must be less than {1} characters")]
    public string LastName { get; set; }

    [Required]
    [MinLength(1, ErrorMessage = "Must contain at least {1} element")]
    [JsonProperty (ItemConverterType = typeof(StringEnumConverter))]
    public UserRole[] Roles { get; set; }
}