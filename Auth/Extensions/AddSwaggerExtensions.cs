using Microsoft.OpenApi.Models;

namespace Auth.Extensions
{
    public static class AddSwaggerExtensions
    {
        public static IServiceCollection AddSwagger(this IServiceCollection services)
        {
            services.AddSwaggerGen(options =>
             {
                 options.SwaggerDoc("v1", new OpenApiInfo
                 {
                     Title = "Minimal API with JWT",
                     Version = "v1"
                 });

                 // Add JWT Authentication to Swagger
                 options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                 {
                     Name = "Authorization",
                     Type = SecuritySchemeType.Http,
                     Scheme = "Bearer",
                     BearerFormat = "JWT",
                     In = ParameterLocation.Header,
                     Description = "Enter your JWT token: Bearer {your token}"
                 });

                 options.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        Array.Empty<string>()
                    }
                });
             });

            return services;
        }
    }
}
