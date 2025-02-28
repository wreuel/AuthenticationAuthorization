using Auth.Models;
using System.Security.Claims;

namespace Auth.Authorizations.User
{
    public class CurrentUser
    {
        public ApplicationUser? User { get; set; }
        public ClaimsPrincipal Principal { get; set; } = default!;

        public string Id => Principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
        public bool IsAdmin => Principal.IsInRole("Admin");
    }

}
