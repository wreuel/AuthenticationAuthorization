using Auth.Authorizations.User;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace Auth.Authorizations.AdminByPass
{
    public class AdminBypassClaimsHandler(CurrentUser currentUser) : AuthorizationHandler<ClaimsAuthorizationRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ClaimsAuthorizationRequirement requirement)
        {
            if (currentUser.User is not null)
            {
                if (currentUser.IsAdmin)
                {
                    context.Succeed(requirement);
                    return Task.CompletedTask;
                }

                // If user is in "Admin" role, automatically succeed
                //if (context.User.IsInRole("Admin"))
                //{
                //    context.Succeed(requirement);
                //    return Task.CompletedTask;
                //}

                // Otherwise, enforce the RequireClaim logic
                if (requirement.ClaimType != null &&
                    context.User.HasClaim(c => c.Type == requirement.ClaimType && requirement.AllowedValues.Contains(c.Value)))
                {
                    context.Succeed(requirement);
                }
            }

            return Task.CompletedTask;
        }
    }
}
