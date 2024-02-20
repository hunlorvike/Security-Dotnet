using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using CustomSecurityDotnet.Data;
using CustomSecurityDotnet.Dtos;
using CustomSecurityDotnet.Entities;
using CustomSecurityDotnet.Utils;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Microsoft.IdentityModel.Tokens;

namespace CustomSecurityDotnet.Controllers
{
    [Route("Auth")]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IStringLocalizer<AuthController> _localizer;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            ApplicationDbContext context,
            IStringLocalizer<AuthController> localizer,
            RoleManager<ApplicationRole> roleManager
        )
        {
            _context = context;
            _userManager = userManager;
            _localizer = localizer;
            _roleManager = roleManager;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register(RegisterDto registerDto)
        {
            var applicationUser = new ApplicationUser()
            {
                UserName = registerDto.UserName,
                Email = registerDto.Email,
                Name = registerDto.Name,
                IsActive = true,
                CreateDate = DateTime.UtcNow,
            };

            try
            {
                var result = await _userManager.CreateAsync(applicationUser, registerDto.Password);

                if (result.Succeeded)
                {
                    var defaultRole = AppConstants.DefaultUserRole;
                    if (!await _roleManager.RoleExistsAsync(defaultRole))
                    {
                        await _roleManager.CreateAsync(new ApplicationRole { Name = defaultRole });
                    }

                    await _userManager.AddToRoleAsync(applicationUser, defaultRole);

                    return Ok(new { message = _localizer["User registered successfully."].Value });
                }
                else
                {
                    return BadRequest(new { errors = result.Errors });
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = $"{ex.GetType().Name}: {ex.Message}" });
            }
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login(LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);

            if (user != null)
            {
                if (await _userManager.CheckPasswordAsync(user, loginDto.Password))
                {
                    var claims = new List<Claim> { new Claim("UserID", user.Id.ToString()), };

                    var userRoles = await _userManager.GetRolesAsync(user);

                    claims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(claims),
                        Expires = DateTime.UtcNow.AddDays(1),
                        SigningCredentials = new SigningCredentials(
                            new SymmetricSecurityKey(
                                Encoding.UTF8.GetBytes(
                                    "aLongSecretStringWhoseBitnessIsEqualToOrGreaterThanTheBitnessOfTheTokenEncryptionAlgorithm"
                                )
                            ),
                            SecurityAlgorithms.HmacSha256Signature
                        )
                    };

                    var tokenHandler = new JwtSecurityTokenHandler();
                    var securityToken = tokenHandler.CreateToken(tokenDescriptor);
                    var token = tokenHandler.WriteToken(securityToken);

                    return Ok(new { token });
                }
            }

            return BadRequest(
                new { error = _localizer["Username or password is incorrect."].Value }
            );
        }

        [HttpPost]
        [Route("Logout")]
        [Authorize]
        public IActionResult Logout()
        {
            return Ok(new { message = _localizer["Logout successful."].Value });
        }

        [HttpGet]
        [Route("Check/UserRole")]
        [Authorize(Roles = AppConstants.DefaultUserRole)]
        public IActionResult CheckUserRole()
        {
            Console.WriteLine("Check role user");
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var userName = User.Identity?.Name;

            var userRoles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();

            return Ok(
                new
                {
                    userId,
                    userName,
                    userRoles,
                    message = $"User {userName} (ID: {userId}) has the required role(s) to access this action."
                }
            );
        }

        [HttpGet]
        [Route("Hello-World")]
        public IActionResult HelloWorld()
        {
            return Ok("Hello World");
        }
    }
}
