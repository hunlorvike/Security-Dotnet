namespace CustomSecurityDotnet.Utils
{
    public enum ERole
    {
        Admin, User, Manager
    }

    public static class ERoleExtensions
    {
        public static string GetRoleString(this ERole role)
        {
            switch (role)
            {
                case ERole.Admin:
                    return "Admin";
                case ERole.User:
                    return "User";
                case ERole.Manager:
                    return "Manager";
                default:
                    throw new ArgumentOutOfRangeException(nameof(role), role, null);
            }
        }

        internal static string? GetRoleString()
        {
            throw new NotImplementedException();
        }
    }
}
