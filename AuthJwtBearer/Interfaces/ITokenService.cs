using AuthJwtBearer.Entities;
using AuthJwtBearer.Models;

namespace AuthJwtBearer.Interfaces
{
    public interface ITokenService
    {
        string GenerateToken(User usuario);

        string GenerateTokenConfirmation(User usuario, TokenModel typeToken);

        string? TokenValidate(string token, TokenModel typeToken);
    }
}
