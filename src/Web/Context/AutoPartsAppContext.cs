using AutoPartsApp.Models.Role;
using AutoPartsApp.Models.RoleClaim;
using AutoPartsApp.Models.User;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AutoPartsApp.Context;

public class AutoPartsAppContext : IdentityDbContext<User, Role, Guid>
{
    public AutoPartsAppContext()
    {
    }
    
    public AutoPartsAppContext(DbContextOptions<AutoPartsAppContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        builder.HasPostgresExtension("uuid-ossp");
        builder.UseSerialColumns();
        base.OnModelCreating(builder);
        // Customize the ASP.NET Identity model and override the defaults if needed.
        // For example, you can rename the ASP.NET Identity table names and more.
        // Add your customizations after calling base.OnModelCreating(builder);
    }
}
