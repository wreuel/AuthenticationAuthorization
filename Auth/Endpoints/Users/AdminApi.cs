namespace Auth.Endpoints.Users
{
    internal static class AdminApi
    {
        public static RouteGroupBuilder MapAdmin(this IEndpointRouteBuilder routes)
        {
            var group = routes.MapGroup("/admin");

            group.WithTags("Admin");


            group.MapGet("/", () =>
            {
                return Results.Ok("Hello Admin!");
            })
           .RequireAuthorization(policy => policy.RequireRole("Admin"));


            return group;
        }
    }
}
