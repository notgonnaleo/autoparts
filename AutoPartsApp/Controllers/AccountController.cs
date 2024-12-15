using AutoPartsApp.Context;
using AutoPartsApp.Models.User;
using AutoPartsApp.Models.User.Request;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AutoPartsApp.Controllers
{
    public class AccountController : Controller
    {
        private readonly AutoPartsAppContext _dbContext;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;

        public AccountController(UserManager<User> userManager, SignInManager<User> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
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