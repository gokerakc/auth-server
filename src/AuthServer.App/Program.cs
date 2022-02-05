using AuthServer.App;
using AuthServer.App.Data;
using AuthServer.App.Data.Seed;
using AuthServer.App.Extensions;
using AuthServer.App.Models;
using AuthServer.App.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using OpenIddict.Validation.AspNetCore;
using Serilog;
using Serilog.Events;

var builder = WebApplication.CreateBuilder(args);

//
// App settings configuration 
//
var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
builder.Configuration
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", false, true)
    .AddJsonFile($"appsettings.{environment}.json", true)
    .AddEnvironmentVariables();

if (string.IsNullOrEmpty(environment) || environment.ToLower() == "development")
{
    builder.Configuration.AddUserSecrets<Program>();
}

//
// Web host configuration
//
var isDevelopment = string.IsNullOrEmpty(environment) || environment.ToLower() == "development";
builder.WebHost.UseKestrel(opt =>
    {
        if (isDevelopment == false)
        {
            opt.ListenAnyIP(80);
        }
    })
    .UseConfiguration(builder.Configuration)
    .UseDefaultServiceProvider((context, options) =>
    {
        options.ValidateScopes = context.HostingEnvironment.IsDevelopment();
    })
    .UseSerilog((ctx, loggerConf) =>
    {
        loggerConf.WriteTo.Console(outputTemplate: "{Timestamp:o} [{Level:u3}] {SourceContext} {Message}{NewLine}{Exception}");
        loggerConf.MinimumLevel.Information();
        loggerConf.MinimumLevel.Override("Microsoft.EntityFrameworkCore.Database.Command", LogEventLevel.Warning);
    });
        
    
//
// Add services to the container
//
builder.Services.AddControllersWithViews()
    .AddNewtonsoftJson(opt =>
    {
        opt.SerializerSettings.DateTimeZoneHandling = DateTimeZoneHandling.Utc;
        opt.SerializerSettings.DateFormatString = "o";
        opt.SerializerSettings.Converters.Add(new StringEnumConverter());
        opt.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;
        opt.UseCamelCasing(true);
    });

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = "/account/login";
    });

builder.Services.AddHealthChecks();

builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy(Constants.TestPolicyName, policy =>
    {
        policy.AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("scope", Constants.TestScope);
    });
});

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(connectionString,
        providerOptions =>
            providerOptions
                .CommandTimeout(60)
                .EnableRetryOnFailure());

    options.UseOpenIddict();
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(opt => opt.SignIn.RequireConfirmedAccount = false)
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.AddOpenIdDict();

builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IOpenIddictApplicationService, OpenIddictApplicationService>();

builder.Services.AddHostedService<SeedScopesService>();
builder.Services.AddHostedService<SeedTestClientService>();
builder.Services.AddHostedService<SeedRolesService>();

var app = builder.Build();

//
// Configure the HTTP request pipeline.
//
var forwardOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto |
                       ForwardedHeaders.XForwardedHost,
    RequireHeaderSymmetry = false
};

forwardOptions.KnownNetworks.Clear();
forwardOptions.KnownProxies.Clear();

app.UseForwardedHeaders(forwardOptions);

app.UseHealthChecks("/ready");

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UsePathBase("/oauth");

app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute();
});

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{returnUrl?}");

app.Run();
