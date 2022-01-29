using System.Security.Cryptography.X509Certificates;
using AuthServer.App.Data;

namespace AuthServer.App.Extensions;

public static class ApplicationBuilderExtensions
{
    public static WebApplicationBuilder AddOpenIdDict(this WebApplicationBuilder builder)
    {
        builder.Services.AddOpenIddict()

            // Register the OpenIddict core components.
            .AddCore(options =>
            {
                // Configure OpenIddict to use the EF Core stores/models.
                options.UseEntityFrameworkCore()
                    .UseDbContext<ApplicationDbContext>();
            })

            // Register the OpenIddict server components.
            .AddServer(options =>
            {
                options
                    .AllowClientCredentialsFlow()
                    .AllowAuthorizationCodeFlow();
                //.RequireProofKeyForCodeExchange();

                options
                    .SetTokenEndpointUris("/connect/token")
                    .SetAuthorizationEndpointUris("/connect/authorize")
                    .SetCryptographyEndpointUris("/.well-known/openid-configuration/jwks");

                if (builder.Environment.IsDevelopment())
                {
                    options
                        .AddDevelopmentSigningCertificate()
                        .AddDevelopmentEncryptionCertificate()
                        .DisableAccessTokenEncryption();
                }
                else
                {
                    var key = builder.Configuration.GetValue<string>("OAuth:SigningKey");
                    var pfxBytes = Convert.FromBase64String(key);
                    var cert = new X509Certificate2(pfxBytes, (string?)null);

                    options
                        .AddSigningCertificate(cert)
                        .AddEncryptionCertificate(cert)
                        .DisableAccessTokenEncryption();
                }

                // Register scopes (permissions)
                options.RegisterScopes(Constants.AllScopes);

                options.RegisterClaims(new[] { "role", "email" });

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options
                    .UseAspNetCore()
                    .DisableTransportSecurityRequirement()
                    .EnableTokenEndpointPassthrough()
                    .EnableAuthorizationEndpointPassthrough();
            })

            // Register the OpenIddict validation components.
            .AddValidation(options =>
            {
                // Import the configuration from the local OpenIddict server instance.
                options.UseLocalServer();

                // Register the ASP.NET Core host.
                options.UseAspNetCore();
            });


        return builder;
    }
}