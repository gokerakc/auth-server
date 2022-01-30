namespace AuthServer.App.Models;

public class LoginRequest
{
    public string Username { get; set; }

    public string ClientId { get; set; }

    public string Scope { get; set; }

    public string RedirectUri { get; set; }

    public string CodeChallenge { get;set; }

    public string CodeChallengeMethod { get;set; }

    public string State { get; set; }

    public string Nonce { get; set; }
}