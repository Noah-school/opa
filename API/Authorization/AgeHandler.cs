using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace API.Authorization
{
    public class AgeHandler : AuthorizationHandler<AgeRequirement>
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AgeHandler(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AgeRequirement requirement)
        {
            if (!context.User.HasClaim(c => c.Type == "age"))
            {
                return;
            }

            var ageClaim = context.User.FindFirst(c => c.Type == "age")?.Value;
            if (!string.IsNullOrEmpty(ageClaim) && int.TryParse(ageClaim, out var age))
            {
                var httpContext = _httpContextAccessor.HttpContext;
                if (httpContext == null)
                {
                    return;
                }

                // Enable buffering so the request can be read multiple times
                httpContext.Request.EnableBuffering();

                // Read the request body
                using (var reader = new StreamReader(httpContext.Request.Body, leaveOpen: true))
                {
                    var body = await reader.ReadToEndAsync();
                    // Reset the request body stream position so the next middleware can read it
                    httpContext.Request.Body.Position = 0;

                    // Deserialize the body to Drink
                    var drink = JsonSerializer.Deserialize<Drink>(body);

                    if (drink != null && (age >= requirement.MinimumAge || drink.DrinkName == "Fristi"))
                    {
                        context.Succeed(requirement);
                    }
                }
            }
        }
    }
}