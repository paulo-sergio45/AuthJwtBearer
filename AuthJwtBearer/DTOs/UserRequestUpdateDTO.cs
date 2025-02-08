using AuthJwtBearer.Entities;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace AuthJwtBearer.DTOs
{

    public class UserRequestUpdateDTO
    {

        [Key]
        public required Guid Id { get; set; }

        public required string UserName { get; set; }

        [PasswordPropertyText]
        public required string Password { get; set; }

        public required UserTypes UserType { get; set; }

        [Required]
        [EmailAddress]
        public required string Email { get; set; }
    }

}
