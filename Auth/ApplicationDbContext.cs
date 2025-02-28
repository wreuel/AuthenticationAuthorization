using Auth.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Auth
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {


        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.Entity<RefreshTokens>()
                .HasOne<ApplicationUser>()
                .WithMany()
                .HasForeignKey(r => r.UserId)
                .HasPrincipalKey(r => r.Id);

            base.OnModelCreating(builder);
        }


        public DbSet<RefreshTokens> RefreshTokens => Set<RefreshTokens>();
    }
}
