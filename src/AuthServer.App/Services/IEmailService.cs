namespace AuthServer.App.Services;

public interface IEmailService
{
    public void SendVerificationEmail(string confirmationLink);
}