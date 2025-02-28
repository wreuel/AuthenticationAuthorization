﻿using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi.Models;

namespace Auth.Extensions
{
    public static class OpenApiOptionsExtensions
    {
        public static OpenApiOptions AddBearerTokenAuthentication(this OpenApiOptions options)
        {
            var scheme = new OpenApiSecurityScheme()
            {
                Type = SecuritySchemeType.Http,
                Name = JwtBearerDefaults.AuthenticationScheme,
                Scheme = "Bearer",
                Reference = new()
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = JwtBearerDefaults.AuthenticationScheme
                }
            };
            options.AddDocumentTransformer((document, context, cancellationToken) =>
            {
                document.Components ??= new();
                document.Components.SecuritySchemes.Add(JwtBearerDefaults.AuthenticationScheme, scheme);
                return Task.CompletedTask;
            });
            options.AddOperationTransformer((operation, context, cancellationToken) =>
            {
                if (context.Description.ActionDescriptor.EndpointMetadata.OfType<IAuthorizeData>().Any())
                {
                    operation.Security = [new() { [scheme] = [] }];
                }
                return Task.CompletedTask;
            });
            return options;
        }
    }
}
