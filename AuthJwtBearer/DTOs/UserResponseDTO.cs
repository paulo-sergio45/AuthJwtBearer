using System.ComponentModel.DataAnnotations;

namespace AuthJwtBearer.DTOs
{
    public class UserResponseDTO
    {

        [Key]
        public Guid Id { get; set; }

        [Required]
        public required string UserName { get; set; }

        [Required]
        [EmailAddress]
        public required string Email { get; set; }
    }

}
