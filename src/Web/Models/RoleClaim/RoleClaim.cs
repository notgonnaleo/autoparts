﻿using Microsoft.AspNetCore.Identity;

namespace AutoPartsApp.Models.RoleClaim
{
    public class RoleClaim : IdentityRoleClaim<Guid>
    {
    }

    public class UserClaim : IdentityUserClaim<Guid> 
    { 
    }

}