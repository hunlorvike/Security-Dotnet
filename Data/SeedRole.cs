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
                    Name = ERole.Admin.ToString(), 
                    NormalizedName = ERole.Admin.ToString()
                },
                new IdentityRole
                {
                    Name = ERole.Manager.ToString(),  
                    NormalizedName = ERole.Manager.ToString()
                },
                new IdentityRole
                {
                    Name = ERole.User.ToString(),
                    NormalizedName = ERole.User.ToString()
                }
            );
        }
    }
}
