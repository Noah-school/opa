using Microsoft.AspNetCore.Authorization;

namespace API.Authorization
{
    public class AgeRequirement : IAuthorizationRequirement
    {
        public int MinimumAge { get; }

        public AgeRequirement(int minimumAge)
        {
            MinimumAge = minimumAge;
        }
    }
}
