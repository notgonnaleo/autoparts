using Microsoft.AspNetCore.Identity;

namespace AutoPartsApp.Models.UserRole
{
    public class UserRole : IdentityUserRole<Guid>
    {
        public string UserName { get; set; }
        public string RoleName { get; set; }
    }
}
