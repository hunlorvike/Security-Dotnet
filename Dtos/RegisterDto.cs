using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CustomSecurityDotnet.Dtos
{
    public class RegisterDto
    {
        [Display(Name = "UserName")]
        [Required(ErrorMessage = "The {0} field is mandatory.")]
        public string? UserName { get; set; } 

        [Display(Name = "Email")]
        [Required(ErrorMessage = "The {0} field is mandatory.")]
        [EmailAddress(ErrorMessage = "Incorrect email address.")]
        public string? Email { get; set; } = string.Empty;

        [Display(Name = "Password")]
        [Required(ErrorMessage = "The {0} field is mandatory.")]
        [StringLength(
            16,
            ErrorMessage = "The {0} must be between {2} and {1} characters long.",
            MinimumLength = 8
        )]
        public string? Password { get; set; }

        [Display(Name = "FullName")]
        [Required(ErrorMessage = "The {0} field is mandatory.")]
        public string? Name { get; set; } = string.Empty;
    }
}
