
using AuthJwtBearer.DTOs;
using System.Security.Cryptography;

namespace AuthJwtBearer.Interfaces
{
    public interface IPasswordHelper
    {
        byte[] HashPasswordV2(string password, RandomNumberGenerator rng);

        bool VerifyHashedPasswordV2(byte[] hashedPassword, string password);

        PasswordValidatorResponseDTO PasswordValidator(string password, int lengthMin, int lengthMax, int? lowercase, int? uppercase, int? symbols, int? digit);
    }
}
