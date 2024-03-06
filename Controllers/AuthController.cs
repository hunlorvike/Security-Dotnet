using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using CustomSecurityDotnet.Dtos.Auth;
using CustomSecurityDotnet.Entities;
using CustomSecurityDotnet.Services;
using CustomSecurityDotnet.Utils;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Localization;
using Microsoft.IdentityModel.Tokens;

namespace CustomSecurityDotnet.Controllers
{
    [ApiController]
    [Route("auth")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly IStringLocalizer<AuthController> _localizer;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
            IStringLocalizer<AuthController> localizer,
            IWebHostEnvironment webHostEnvironment
        )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _localizer = localizer;
            _webHostEnvironment = webHostEnvironment;
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register(RegisterDto registerDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var applicationUser = new ApplicationUser()
            {
                UserName = registerDto.UserName,
                Email = registerDto.Email,
                Name = registerDto.Name,
                IsActive = false,
                CreateDate = DateTime.UtcNow,
            };

            try
            {
                var result = await _userManager.CreateAsync(applicationUser, registerDto.Password ?? "");

                if (result.Succeeded)
                {
                    var defaultRoleExists = await _roleManager.RoleExistsAsync(
                        ERole.User.ToString()
                    );
                    if (!defaultRoleExists)
                    {
                        await _roleManager.CreateAsync(
                            new ApplicationRole { Name = ERole.User.ToString() }
                        );
                    }

                    await _userManager.AddToRoleAsync(applicationUser, ERole.User.ToString());

                    var emailConfirmationToken =
                        await _userManager.GenerateEmailConfirmationTokenAsync(applicationUser);
                    emailConfirmationToken = WebEncoders.Base64UrlEncode(
                        Encoding.UTF8.GetBytes(emailConfirmationToken)
                    );

                    var callBackUrl =
                        $"http://localhost:5000/auth/confirm-email?userId={applicationUser.Id}&code={emailConfirmationToken}";

                    string body = string.Empty;
                    var htmlFilePath = Path.Combine(
                        _webHostEnvironment.ContentRootPath,
                        "Utils/Html/boileremail.html"
                    );

                    using (StreamReader reader = new StreamReader(htmlFilePath))
                    {
                        body = reader.ReadToEnd();
                    }
                    body = body.Replace("{redirectVerify}", callBackUrl);
                    body = body.Replace("{UserName}", registerDto.Email);

                    bool isSendEmail = SendEmail.EmailSend(
                        registerDto.Email ?? "",
                        "Confirm your account",
                        body,
                        true
                    );

                    if (isSendEmail)
                    {
                        return Ok(
                            new
                            {
                                message = _localizer[
                                    "User registered successfully. Please check your email to confirm your account."
                                ].Value
                            }
                        );
                    }
                    else
                    {
                        return BadRequest(
                            new { error = _localizer["Failed to send confirmation email."].Value }
                        );
                    }
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
        [Route("login")]
        public async Task<IActionResult> Login(LoginDto loginDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await _userManager.FindByNameAsync(loginDto.UserName ?? "");

            if (user != null && await _userManager.CheckPasswordAsync(user, loginDto.Password ?? ""))
            {
                if (!user.IsActive)
                {
                    return BadRequest(new { error = _localizer["User is not activated."].Value });
                }

                var claims = new List<Claim>
                {
                    new Claim("UserId", user.Id.ToString()),
                    new Claim(ClaimTypes.Name, user.UserName ?? ""),
                };

                var userRoles = await _userManager.GetRolesAsync(user);
                claims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes(
                                "aLongSecretStringWhoseBitnessIsEqualToOrGreaterThanTheBitnessOfTheTokenEncryptionAlgorithm"
                            )
                        ),
                        SecurityAlgorithms.HmacSha256Signature
                    ),
                    Issuer = "127.0.0.1:5000",
                    Audience = "127.0.0.1:5000",
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var securityToken = tokenHandler.CreateToken(tokenDescriptor);
                var token = tokenHandler.WriteToken(securityToken);

                return Ok(new { token });
            }

            return BadRequest(
                new { error = _localizer["Username or password is incorrect."].Value }
            );
        }

        [HttpGet]
        [Route("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(
            [FromQuery(Name = "userId")] string userId,
            [FromQuery(Name = "code")] string code
        )
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
            {
                return BadRequest(new { error = _localizer["Invalid confirmation link."].Value });
            }

            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return BadRequest(new { error = _localizer["User not found."].Value });
            }
            var decodedCode = WebEncoders.Base64UrlDecode(code);
            var result = await _userManager.ConfirmEmailAsync(
                user,
                Encoding.UTF8.GetString(decodedCode)
            );

            if (result.Succeeded)
            {
                user.IsActive = true;
                await _userManager.UpdateAsync(user);

                return Ok(new { message = _localizer["Email confirmed successfully."].Value });
            }
            else
            {
                return BadRequest(new { error = _localizer["Email confirmation failed."].Value });
            }
        }

        [HttpPost]
        [Route("forgot-password")]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordDto forgotPasswordDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await _userManager.FindByEmailAsync(forgotPasswordDto.Email ?? "");

            if (user == null)
            {
                return Ok(
                    new { message = _localizer["Password reset link sent successfully."].Value }
                );
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            var callbackUrl =
                $"http://localhost:5000/auth/reset-password?userId={user.Id}&token={encodedToken}";

            string body = string.Empty;
            var htmlFilePath = Path.Combine(
                _webHostEnvironment.ContentRootPath,
                "Utils/Html/boileremail.html"
            );

            using (StreamReader reader = new StreamReader(htmlFilePath))
            {
                body = reader.ReadToEnd();
            }
            body = body.Replace("{redirectVerify}", callbackUrl);
            body = body.Replace("{UserName}", user.Email);

            bool isSendEmail = SendEmail.EmailSend(
                user.Email ?? "",
                "Reset your password",
                body,
                true
            );

            if (isSendEmail)
            {
                return Ok(
                    new { message = _localizer["Password reset link sent successfully."].Value }
                );
            }
            else
            {
                return BadRequest(
                    new { error = _localizer["Failed to send reset password email."].Value }
                );
            }
        }

        [HttpPost]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPasswordDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await _userManager.FindByIdAsync(resetPasswordDto.UserId ?? "");

            if (user == null)
            {
                return BadRequest(new { error = _localizer["User not found."].Value });
            }

            var decodedToken = WebEncoders.Base64UrlDecode(resetPasswordDto.Token ?? "");
            var token = Encoding.UTF8.GetString(decodedToken);

            var result = await _userManager.ResetPasswordAsync(
                user,
                token,
                resetPasswordDto.NewPassword ?? ""
            );

            if (result.Succeeded)
            {
                return Ok(new { message = _localizer["Password reset successfully."].Value });
            }
            else
            {
                return BadRequest(new { error = _localizer["Password reset failed."].Value });
            }
        }

        [HttpPost]
        [Route("logout")]
        [Authorize]
        public IActionResult Logout()
        {
            return Ok(new { message = _localizer["Logout successful."].Value });
        }

        [HttpGet]
        [Route("check/role-user")]
        [Authorize(Roles = "User")]
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
        [Route("check/role-admin")]
        [Authorize(Roles = "Admin")]
        public IActionResult CheckAdminRole()
        {
            Console.WriteLine("Check role admin");
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
    }
}
