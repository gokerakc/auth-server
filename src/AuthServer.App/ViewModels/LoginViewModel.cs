using System.ComponentModel.DataAnnotations;

namespace AuthServer.App.ViewModels;

public class LoginViewModel
{
    [Required(ErrorMessage = "Please enter a valid email")]
    public string Email { get; set; }
    
    [Required(ErrorMessage = "Please enter a valid password")]
    public string Password { get; set; }

    public string ReturnUrl { get; set; }

    public LoginViewModel()
    {
    }

    public LoginViewModel(string email, string password, string returnUrl)
    {
        Email = email;
        Password = password;
        ReturnUrl = returnUrl;
    }
}