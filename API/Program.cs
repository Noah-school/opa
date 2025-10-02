using API.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using OpenPolicyAgent.Opa;
using OpenPolicyAgent.Opa.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Read values from appsettings.json
var jwtAuthority = builder.Configuration["Jwt:Authority"];
var jwtAudience = builder.Configuration["Jwt:Audience"];
var corsOrigin = builder.Configuration["Cors:Origin"];

// Add services to the container.

builder.Services.AddControllers();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.Authority = jwtAuthority;
    options.Audience = jwtAudience;
    options.RequireHttpsMetadata = false;
});

builder.Services.AddHttpContextAccessor();

// builder.Services.AddAuthorization(options =>
// {
//     options.FallbackPolicy = new AuthorizationPolicyBuilder()
//         .RequireAuthenticatedUser()
//         .Build();
//     options.AddPolicy("Over16Only", policy =>
//             policy.Requirements.Add(new AgeRequirement(16)));
// });
// builder.Services.AddSingleton<IAuthorizationHandler, AgeHandler>();

var app = builder.Build();

var opaUrl = "http://opa:8181";
var opaClient = new OpaClient(opaUrl);

app.UseCors(options => options
    .WithOrigins(corsOrigin ?? "http://localhost:3000")
    .AllowAnyMethod()
    .AllowAnyHeader());

app.UseAuthentication();
app.UseAuthorization();

app.UseMiddleware<OpaAuthorizationMiddleware>(opaClient, "example/allow");

app.MapControllers();

app.Run();
