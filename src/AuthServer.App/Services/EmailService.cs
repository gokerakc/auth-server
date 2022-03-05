using System.Diagnostics;

namespace AuthServer.App.Services;

public class EmailService : IEmailService
{
    //TODO: Implement an email sender
    public void SendVerificationEmail(string confirmationLink)
    {
        Debug.WriteLine(confirmationLink);
    }
}