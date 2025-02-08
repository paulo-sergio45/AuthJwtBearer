using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace AuthJwtBearer.DTOs
{
    public class UserLoginDTO
    {
        [Required]
        [EmailAddress]
        public required string Email { get; set; }

        [Required]
        [PasswordPropertyText]
        public required string Password { get; set; }
    }

}
