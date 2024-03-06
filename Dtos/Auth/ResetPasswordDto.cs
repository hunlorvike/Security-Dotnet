using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CustomSecurityDotnet.Dtos.Auth
{
    public class ResetPasswordDto
    {
        [Required(ErrorMessage = "User Id không được để trống")]
        public string? UserId { get; set; }

        [Required(ErrorMessage = "Token không được để trống")]
        public string? Token { get; set; }

        [Required(ErrorMessage = "Mật khẩu mới không được để trống không được để trống")]
        public string? NewPassword { get; set; }
    }
}
