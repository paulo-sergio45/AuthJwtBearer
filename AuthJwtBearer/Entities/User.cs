namespace AuthJwtBearer.Entities
{

    public class User
    {
        public required Guid Id { get; set; }

        public required string UserName { get; set; }

        public required string Password { get; set; }

        public required UserTypes UserType { get; set; }

        public required string Email { get; set; }

        public required bool EmailConfirmed { get; set; }

        public bool IsActive { get; set; }
    }

    public enum UserTypes : ushort
    {
        Admin = 0,
        User = 1
    }


}
