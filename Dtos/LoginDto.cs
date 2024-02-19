using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CustomSecurityDotnet.Dtos
{
    public class LoginDto
    {
        [Required(ErrorMessage = "Tài khoản không được để trống")]
        public string? UserName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Mật khẩu không được để trống")]
        [DataType(DataType.Password)]
        public string? Password { get; set; } = string.Empty;

    }
}