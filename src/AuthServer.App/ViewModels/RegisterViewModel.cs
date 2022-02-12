using System.ComponentModel.DataAnnotations;

namespace AuthServer.App.ViewModels;

public class RegisterViewModel
{
    public string FirstName { get; set; }
    
    public string LastName { get; set; }
    
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress]
    public string Email { get; set; }
    
    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    public string Password { get; set; }
    
    [DataType(DataType.Password)]
    [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
    public string ConfirmPassword { get; set; }

    public RegisterViewModel()
    {
    }

    public RegisterViewModel(string firstName, string lastName, string email, string password, string confirmedPassword)
    {
        FirstName = firstName;
        LastName = lastName;
        Email = email;
        Password = password;
        ConfirmPassword = confirmedPassword;
    }
}