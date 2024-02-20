using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CustomSecurityDotnet.Utils;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CustomSecurityDotnet.Data
{
    public class SeedRole : IEntityTypeConfiguration<IdentityRole>
    {
        public void Configure(EntityTypeBuilder<IdentityRole> builder)
        {
            builder.HasData(
                new IdentityRole
                {
                    Name = AppConstants.DefaultUserRole,
                    NormalizedName = AppConstants.DefaultUserRole.ToUpper()
                },
                new IdentityRole
                {
                    Name = AppConstants.AdminRole,
                    NormalizedName = AppConstants.AdminRole.ToUpper()
                },
                new IdentityRole
                {
                    Name = AppConstants.ManagerRole,
                    NormalizedName = AppConstants.ManagerRole.ToUpper()
                }
            );
        }
    }
}
