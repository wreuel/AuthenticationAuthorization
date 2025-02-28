namespace Auth.Endpoints.Users
{
    internal static class SecretaryApi
    {
        public static RouteGroupBuilder MapSecretary(this IEndpointRouteBuilder routes)
        {
            var group = routes.MapGroup("/secretary");

            group.WithTags("Secretary");


            group.MapGet("/", () =>
            {
                return Results.Ok("Hello, Secretary!");
            })
           .RequireAuthorization(policy => policy.RequireRole("Secretary"));


            return group;
        }
    }
}
