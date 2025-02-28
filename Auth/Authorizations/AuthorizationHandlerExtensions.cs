using Auth.Authorizations.AdminByPass;
using Auth.Authorizations.RoleOrClaim;
using Auth.Authorizations.User;
using Microsoft.AspNetCore.Authorization;

namespace Auth.Authorizations
{
    public static class AuthorizationHandlerExtensions
    {
        public static AuthorizationBuilder AddAdminByPassClaims(this AuthorizationBuilder builder)
        {
            builder.Services.AddScoped<IAuthorizationHandler, AdminBypassClaimsHandler>();
            return builder;
        }

        public static AuthorizationBuilder AddAdminByPassRoles(this AuthorizationBuilder builder)
        {
            builder.Services.AddScoped<IAuthorizationHandler, AdminByPassRolesHandler>();
            return builder;
        }

        public static AuthorizationBuilder AddRoleOrClaim(this AuthorizationBuilder builder)
        {
            builder.Services.AddScoped<IAuthorizationHandler, RoleOrClaimAuthHandler>();
            return builder;
        }

        public static AuthorizationBuilder AddCurrentUserHandler(this AuthorizationBuilder builder)
        {
            builder.Services.AddScoped<IAuthorizationHandler, CheckCurrentUserAuthHandler>();
            return builder;
        }
    }
}
