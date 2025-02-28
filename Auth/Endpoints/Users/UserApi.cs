using Auth.Authorizations.Policies;
using Auth.Authorizations.User;
using Auth.Dtos;
using Auth.Models;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Auth.Endpoints.Users
{
    internal static class UserAPi
    {
        public static RouteGroupBuilder MapUsers(this IEndpointRouteBuilder routes)
        {
            var group = routes.MapGroup("/users");

            group.WithTags("Users");

            group.MapPost("/register", async (UserManager<ApplicationUser> userManager, string email, string password) =>
            {
                var user = new ApplicationUser { UserName = email, Email = email };
                var result = await userManager.CreateAsync(user, password);

                if (result.Succeeded)
                    return Results.Ok("User registered successfully!");

                return Results.BadRequest(result.Errors);
            });

            group.MapPost("/login", async (UserInfo userInfo, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager,
                IConfiguration config, ApplicationDbContext db) =>
            {
                var user = await userManager.FindByEmailAsync(userInfo.UserName);
                if (user == null)
                    return Results.Unauthorized();

                var result = await signInManager.PasswordSignInAsync(user, userInfo.Password, false, false);
                if (!result.Succeeded)
                    return Results.Unauthorized();

                List<Claim> claims = await GetRolesAndClaims(userManager, user);

                var token = GenerateJwtToken(user, claims, config);
                var refreshToken = await GenerateRefreshTokenAsync(user.Id, db);

                return Results.Ok(new { token, refreshToken });
            });

            group.MapPost("/refresh", async (IConfiguration config, string refreshToken, UserManager<ApplicationUser> userManager, ApplicationDbContext db) =>
            {
                // In production, store and verify refresh tokens securely

                var refres = await db.RefreshTokens.FirstAsync(rf => rf.RefreshToken == refreshToken);

                if (refres != null && refres.ValidTo >= DateTimeOffset.UtcNow)
                {
                    var user = await userManager.FindByIdAsync(refres.UserId);
                    if (user != null)
                    {
                        var claims = await GetRolesAndClaims(userManager, user);
                        var token = GenerateJwtToken(user, claims, config);
                        refreshToken = await GenerateRefreshTokenAsync(user.Id, db);
                        return Results.Ok(new { token, refreshToken });
                    }
                }

                return Results.Unauthorized();
            });


            group.MapGet("/authenticated", (CurrentUser currentUser) =>
            {
                if (currentUser.User is null)
                    return Results.Unauthorized();

                return Results.Ok(new { currentUser.User.Email, currentUser.Id, currentUser.IsAdmin });
            }).RequireAuthorization(policy => policy.RequireAuthenticatedUser());


            group.MapGet("/currentUser", (CurrentUser currentUser) =>
            {
                if (currentUser.User is null)
                    return Results.Unauthorized();

                return Results.Ok(new { currentUser.User.Email, currentUser.Id, currentUser.IsAdmin });
            }).RequireAuthorization(policy => policy.RequireCurrentUser());

            group.MapGet("/api/user", (ClaimsPrincipal user) =>
            {
                return Results.Ok($"Hello, {user.Identity?.Name}");
            }).RequireAuthorization();


            group.MapPost("/token/{provider}", async Task<Results<Ok<AccessTokenResponse>, SignInHttpResult, ValidationProblem>> (string provider, ExternalUserInfo userInfo, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IDataProtectionProvider dataProtectionProvider) =>
            {
                // Protecting the provider key
                var protector = dataProtectionProvider.CreateProtector(provider);

                // Unprotect the provider key from the user info
                var providerKey = protector.Unprotect(userInfo.ProviderKey);

                // Try to find the user by external login provider key
                var user = await userManager.FindByLoginAsync(provider, providerKey);

                IdentityResult result = IdentityResult.Success;

                if (user is null)
                {
                    // If the user does not exist, create a new user
                    user = new ApplicationUser { UserName = userInfo.Username };

                    result = await userManager.CreateAsync(user);

                    if (result.Succeeded)
                    {
                        // Link the user with the external login provider (Google, GitHub, etc.)
                        result = await userManager.AddLoginAsync(user, new UserLoginInfo(provider, providerKey, userInfo.Username));
                    }
                }

                if (result.Succeeded)
                {
                    // Sign in the user and return a token or a user principal
                    var principal = await signInManager.CreateUserPrincipalAsync(user);
                    return TypedResults.SignIn(principal);
                }

                // If the result failed, return validation problem with the errors
                return TypedResults.ValidationProblem(result.Errors.ToDictionary(e => e.Code, e => new[] { e.Description }));
            });


            return group;
        }

        private static async Task<List<Claim>> GetRolesAndClaims(UserManager<ApplicationUser> userManager, ApplicationUser user)
        {
            var roles = await userManager.GetRolesAsync(user);
            List<Claim> claims = [];
            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var claimsAssigned = await userManager.GetClaimsAsync(user);

            claims.AddRange(claimsAssigned);
            return claims;
        }

        static string GenerateJwtToken(ApplicationUser user, List<Claim> claims, IConfiguration config)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            claims.Add(new(ClaimTypes.Name, user.UserName));
            claims.Add(new(ClaimTypes.NameIdentifier, user.Id));

            var token = new JwtSecurityToken(
                claims: claims,
                audience: "https://locahost",
                issuer: "https://locahost",
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        static async Task<string> GenerateRefreshTokenAsync(string userId, ApplicationDbContext db)
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            string refreshToken = Convert.ToBase64String(randomNumber);

            RefreshTokens refresh = new RefreshTokens
            {
                Id = new Guid(),
                RefreshToken = refreshToken,
                ValidTo = DateTimeOffset.UtcNow.AddHours(1),
                UserId = userId
            };

            db.RefreshTokens.Add(refresh);
            await db.SaveChangesAsync();

            return refreshToken;
        }

    }
}
