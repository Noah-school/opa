using API.Authorization;
using API.Helpers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using OpenPolicyAgent.Opa;
using OpenPolicyAgent.Opa.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

var jwtAuthority = builder.Configuration["Jwt:Authority"];
var jwtAudience = builder.Configuration["Jwt:Audience"];
var corsOrigin = builder.Configuration["Cors:Origin"];


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
builder.Services.AddSingleton<IContextDataProvider, PostBodyContextDataProvider>();


var app = builder.Build();

var opaUrl = "http://opa:8181";
var opaClient = new OpaClient(opaUrl);

app.UseCors(options => options
    .WithOrigins(corsOrigin ?? "http://localhost:3000")
    .AllowAnyMethod()
    .AllowAnyHeader());

app.UseAuthentication();
// app.UseAuthorization();

app.UseMiddleware<OpaAuthorizationMiddleware>(opaClient, "system/main");

app.MapControllers();

app.Run();
