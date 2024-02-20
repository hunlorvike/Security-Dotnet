using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace CustomSecurityDotnet.Entities
{
    public class ApplicationUser : IdentityUser<int>
    {
        public string? Name { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public string? Ip { set; get; }
        public DateTime LastLogin { get; set; }
        public DateTime CreateDate { get; set; }
    }
}
