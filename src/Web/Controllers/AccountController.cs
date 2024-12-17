using AutoPartsApp.Context;
using AutoPartsApp.Models.Role;
using AutoPartsApp.Models.RoleClaim;
using AutoPartsApp.Models.RoleClaim.Request;
using AutoPartsApp.Models.User;
using AutoPartsApp.Models.User.Request;
using AutoPartsApp.Viewmodel.Role;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AutoPartsApp.Controllers
{
    public class AccountController : Controller
    {
        private readonly AutoPartsAppContext _context;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;

        public AccountController(UserManager<User> userManager, SignInManager<User> signInManager, AutoPartsAppContext context)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
        }

        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(string userName, string password, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            var isAuthenticated = await _signInManager.PasswordSignInAsync(userName, password, true, false);
            if (isAuthenticated.Succeeded)
            {
                var claims = new List<Claim>
                {
                    new Claim("user", userName),
                    new Claim("role", "Member")
                };

                await HttpContext.SignInAsync(new ClaimsPrincipal(new ClaimsIdentity(claims, "Cookies", "user", "role")));

                if (Url.IsLocalUrl(returnUrl))
                {
                    return Redirect(returnUrl);
                }
                else
                {
                    return Redirect("/");
                }
            }

            return View();
        }

        [HttpGet]
        public IActionResult Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        public async Task<IdentityResult> Register(NewUserRequest newUser)
        {
            var user = new Models.User.User()
            {
                Email = newUser.EmailAddress,
                UserName = newUser.UserName,
                PhoneNumber = newUser.PhoneNumber,
            };

            var hasher = new PasswordHasher<User>();
            var hashedPassword = hasher.HashPassword(user, newUser.Password);
            user.PasswordHash = hashedPassword;

            return await _userManager.CreateAsync(user);
        }

        [HttpGet]
        public async Task<IActionResult> Roles() 
        {
            var rolesWithClaims = _context.Roles
                .GroupJoin(
                    _context.RoleClaims,
                    role => role.Id,
                    claim => claim.RoleId,
                    (role, claims) => new RoleClaimViewmodel
                    {
                        Role = role,
                        Claims = claims.Select(c => new AutoPartsApp.Models.RoleClaim.RoleClaim
                        {
                            Id = c.Id,
                            RoleId = c.RoleId,
                            ClaimType = c.ClaimType,
                            ClaimValue = c.ClaimValue
                        })
                    }
                );
            return View(rolesWithClaims);
        }

        [HttpPost]
        public async Task<IActionResult> CreateRole(Role newRole)
        {
            newRole.Id = Guid.NewGuid();
            newRole.NormalizedName = newRole.Name.ToUpper();
            newRole.ConcurrencyStamp = newRole.ConcurrencyStamp;
            _context.Roles.Add(newRole);
            _context.SaveChanges();
            return RedirectToAction("Roles");
        }

        [HttpPost]
        public async Task<IActionResult> CreateClaim(NewRoleClaim newRoleClaim)
        {
            _context.RoleClaims.Add(new IdentityRoleClaim<Guid>()
            {
                ClaimType = newRoleClaim.Role.NormalizedName,
                ClaimValue = newRoleClaim.RoleClaim.ClaimValue,
                RoleId = newRoleClaim.Role.Id
            });
            _context.SaveChanges();
            return RedirectToAction("Roles");
        }

        public IActionResult AccessDenied(string returnUrl = null)
        {
            return View();
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return Redirect("/");
        }
    }
}