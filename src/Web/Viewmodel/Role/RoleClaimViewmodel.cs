using AutoPartsApp.Models;
using AutoPartsApp.Models.RoleClaim.Request;
using AutoPartsApp.Models.User;
using AutoPartsApp.Models.UserRole;
using Microsoft.AspNetCore.Identity;

namespace AutoPartsApp.Viewmodel.Role
{
    public class RoleAndClaims
    {
        public Models.Role.Role Role { get; set; }
        public IEnumerable<Models.RoleClaim.RoleClaim> Claims { get; set; }
        public NewRoleClaim NewRoleClaim { get; set; }
    }

    public class RoleClaimViewmodel 
    {
        public IEnumerable<RoleAndClaims>? RoleAndClaims { get; set; }
        public IEnumerable<IdentityUserRole<Guid>>? UserRoles { get; set; }
        public IEnumerable<User>? Users { get; set; }
    }

}
