using Auth.Authorizations;
using Auth.Authorizations.User;
using Auth.Endpoints.Users;
using Auth.Extensions;
using Auth.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using System.Security.Claims;
using System.Text;

namespace Auth
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

            builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddUserManager<UserManager<ApplicationUser>>()
                .AddSignInManager()
                .AddDefaultTokenProviders();

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ClockSkew = TimeSpan.Zero,
                    ValidIssuer = builder.Configuration["Jwt:Issuer"],
                    ValidAudience = builder.Configuration["Jwt:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
                };
            });

            builder.Services.AddCurrentUser();

            builder.Services.AddOpenApi(options => options.AddBearerTokenAuthentication());

            builder.Services.AddAuthorization();

            builder.Services.AddAuthorizationBuilder()
                .AddCurrentUserHandler()
                .AddAdminByPassClaims()
                .AddAdminByPassRoles()
                .AddRoleOrClaim();

            //builder.Services.AddControllers();
            // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi

            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwagger();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.MapScalarApiReference(options =>
                {
                    options.Servers = [];
                    options.Authentication = new() { PreferredSecurityScheme = JwtBearerDefaults.AuthenticationScheme };
                });

                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            await UpdateDatabase(app.Services);
            await SeedDatabaseAsync(app.Services).ConfigureAwait(false);

            app.MapOpenApi();
            app.Map("/", () => Results.Redirect("/scalar/v1"));


            app.MapAdmin();
            app.MapDelivery();
            app.MapUsers();
            app.MapSecretary();

            app.Run();
        }

        private static async Task UpdateDatabase(IServiceProvider services)
        {
            using var scope = services.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var appliedMigrations = await context.Database.GetAppliedMigrationsAsync();
            var availableMigrations = context.Database.GetMigrations();

            bool hasInvalidMigration = appliedMigrations.Any(applied => !availableMigrations.Contains(applied));

            if (hasInvalidMigration)
            {
                await context.Database.EnsureDeletedAsync();
            }

            await context.Database.MigrateAsync();
        }

        async static Task SeedDatabaseAsync(IServiceProvider services)
        {
            using var scope = services.CreateScope();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            string adminEmail = "admin@example.com";
            string secretaryEmail = "secretary@example.com";
            string deliveryEmail = "delivery@example.com";
            string password = "Admin123!";

            // Create roles if they don't exist
            string[] roles = { "Admin", "Secretary", "Delivery" };
            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                    await roleManager.CreateAsync(new IdentityRole(role));
            }

            // Create Admin User
            if (await userManager.FindByEmailAsync(adminEmail) == null)
            {
                var adminUser = new ApplicationUser { UserName = adminEmail, Email = adminEmail };
                await userManager.CreateAsync(adminUser, password);
                await userManager.AddToRoleAsync(adminUser, "Admin");
            }

            // Create Secretary User
            if (await userManager.FindByEmailAsync(secretaryEmail) == null)
            {
                var secretaryUser = new ApplicationUser { UserName = secretaryEmail, Email = secretaryEmail };
                await userManager.CreateAsync(secretaryUser, password);
                await userManager.AddToRoleAsync(secretaryUser, "Secretary");
            }

            if (await userManager.FindByEmailAsync(deliveryEmail) == null)
            {
                List<Claim> claims =
                [
                    new("Custom", "Delivery"),
                        new(ClaimTypes.WindowsUserClaim.ToString(), "Windows")
                ];
                var deliveryUser = new ApplicationUser { UserName = deliveryEmail, Email = deliveryEmail };
                await userManager.CreateAsync(deliveryUser, password);
                await userManager.AddToRoleAsync(deliveryUser, "Delivery");
                await userManager.AddClaimsAsync(deliveryUser, claims);
            }
        }
    }
}
