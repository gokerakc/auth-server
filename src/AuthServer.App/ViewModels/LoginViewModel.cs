using System.ComponentModel.DataAnnotations;

namespace AuthServer.App.ViewModels;

public class LoginViewModel
{
    [Required(ErrorMessage = "Please enter a valid username")]
    public string Username { get; set; }
    
    [Required(ErrorMessage = "Please enter a valid password")]
    public string Password { get; set; }

    public string ReturnUrl { get; set; }

    public LoginViewModel()
    {
    }

    public LoginViewModel(string username, string password, string returnUrl)
    {
        Username = username;
        Password = password;
        ReturnUrl = returnUrl;
    }
}