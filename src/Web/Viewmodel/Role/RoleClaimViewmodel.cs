using AutoPartsApp.Models;
using AutoPartsApp.Models.RoleClaim.Request;

namespace AutoPartsApp.Viewmodel.Role
{
    public class RoleClaimViewmodel
    {
        public Models.Role.Role Role { get; set; }
        public IEnumerable<Models.RoleClaim.RoleClaim> Claims { get; set; }

        public NewRoleClaim NewRoleClaim { get; set; }
    }
}
