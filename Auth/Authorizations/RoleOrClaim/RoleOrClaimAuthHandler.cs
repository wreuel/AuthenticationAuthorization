using Auth.Authorizations.User;
using Microsoft.AspNetCore.Authorization;

namespace Auth.Authorizations.RoleOrClaim
{
    public class RoleOrClaimAuthHandler(CurrentUser currentUser) : AuthorizationHandler<RoleOrClaimRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RoleOrClaimRequirement requirement)
        {
            if (currentUser.User is not null)
            {
                // If user is Admin, grant access immediately
                if (currentUser.IsAdmin)
                {
                    context.Succeed(requirement);
                    return Task.CompletedTask;
                }

                // If a role is required, check if the user has it
                if (!string.IsNullOrEmpty(requirement.Role) && context.User.IsInRole(requirement.Role))
                {
                    context.Succeed(requirement);
                    return Task.CompletedTask;
                }

                // If a claim is required, check if the user has it
                if (!string.IsNullOrEmpty(requirement.ClaimType) &&
                    !string.IsNullOrEmpty(requirement.ClaimValue) &&
                    context.User.HasClaim(requirement.ClaimType, requirement.ClaimValue))
                {
                    context.Succeed(requirement);
                    return Task.CompletedTask;
                }

            }

            return Task.CompletedTask;
        }
    }
}
