using Auth.Authorizations.User;
using Microsoft.AspNetCore.Authorization;

namespace Auth.Authorizations.Policies
{
    public static class PolicyBuilderExtensions
    {
        public static AuthorizationPolicyBuilder RequireCurrentUser(this AuthorizationPolicyBuilder builder)
        {
            return builder.RequireAuthenticatedUser()
                          .AddRequirements(new CheckCurrentUserRequirement());
        }
    }
}
