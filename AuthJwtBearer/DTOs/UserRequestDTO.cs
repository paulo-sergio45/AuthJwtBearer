using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace AuthJwtBearer.DTOs
{

    public class UserRequestDTO
    {
        public required string UserName { get; set; }

        [PasswordPropertyText]
        public required string Password { get; set; }

        [Required]
        [EmailAddress]
        public required string Email { get; set; }
    }

}
