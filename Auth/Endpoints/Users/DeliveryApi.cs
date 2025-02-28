using Auth.Authorizations.RoleOrClaim;
using System.Security.Claims;

namespace Auth.Endpoints.Users
{
    internal static class DeliveryApi
    {
        public static RouteGroupBuilder MapDelivery(this IEndpointRouteBuilder routes)
        {
            var group = routes.MapGroup("/delivery");

            group.WithTags("Delivery");


            group.MapGet("/checkCustom", (ClaimsPrincipal user) =>
            {
                return Results.Ok($"Hello, {user.Identity.Name} you have {string.Join(", ", user.Claims.Select(x => x.Value))}");
            }).RequireAuthorization(policy => policy.RequireClaim("Custom", "Delivery"));


            group.MapGet("/checkRoles", (ClaimsPrincipal user) =>
            {
                return Results.Ok($"Hello, {user.Identity.Name} you have {string.Join(", ", user.Claims.Select(x => x.Value))}");
            }).RequireAuthorization(policy => policy.AddRequirements(new RoleOrClaimRequirement(role: "Delivery")));

            group.MapGet("/checkClaim", (ClaimsPrincipal user) =>
            {
                return Results.Ok($"Hello, {user.Identity.Name} you have {string.Join(", ", user.Claims.Select(x => x.Value))}");
            }).RequireAuthorization(policy => policy.AddRequirements(new RoleOrClaimRequirement(role: null, claimType: ClaimTypes.WindowsUserClaim.ToString(), claimValue: "Windows")));

            return group;
        }
    }
}
