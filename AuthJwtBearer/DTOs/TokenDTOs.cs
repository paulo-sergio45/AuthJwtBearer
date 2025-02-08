using System.ComponentModel.DataAnnotations;

namespace AuthJwtBearer.DTOs
{
    public class TokenDTOs
    {
        [Required]
        public required string Token { get; set; }
    }
}

