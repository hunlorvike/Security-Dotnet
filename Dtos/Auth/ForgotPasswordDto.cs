using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CustomSecurityDotnet.Dtos.Auth
{
    public class ForgotPasswordDto 
    {
        [Required(ErrorMessage = "Email không được để trống")]
        public string? Email { get; set; }
    }
}
