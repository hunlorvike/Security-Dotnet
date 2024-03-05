using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CustomSecurityDotnet.Dtos
{
    public class ResetPasswordDto
    {
        public string? UserId { get; set; }

        [Required]
        public string? Token { get; set; }

        [Required]
        public string? NewPassword { get; set; }
    }
}
