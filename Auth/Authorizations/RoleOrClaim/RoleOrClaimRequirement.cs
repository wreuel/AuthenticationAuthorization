using Microsoft.AspNetCore.Authorization;

namespace Auth.Authorizations.RoleOrClaim
{
    public class RoleOrClaimRequirement : IAuthorizationRequirement
    {
        public RoleOrClaimRequirement(string? role = null, string? claimType = null, string? claimValue = null)
        {
            Role = role;
            ClaimType = claimType;
            ClaimValue = claimValue;
        }

        public string? Role { get; }
        public string? ClaimType { get; }
        public string? ClaimValue { get; }
    }
}
