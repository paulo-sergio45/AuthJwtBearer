using AuthJwtBearer.DTOs;
using AuthJwtBearer.Interfaces;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;

namespace AuthJwtBearer.Helper
{
    public class PasswordHelper : IPasswordHelper

    {
        //referencia AspNetIdentityPasswordHelper
        public byte[] HashPasswordV2(string password, RandomNumberGenerator rng)
        {
            const KeyDerivationPrf Pbkdf2Prf = KeyDerivationPrf.HMACSHA1; // default for Rfc2898DeriveBytes
            const int Pbkdf2IterCount = 1000; // default for Rfc2898DeriveBytes
            const int Pbkdf2SubkeyLength = 256 / 8; // 256 bits
            const int SaltSize = 128 / 8; // 128 bits

            // Produce a version 2 (see comment above) text hash.
            byte[] salt = new byte[SaltSize];
            rng.GetBytes(salt);
            byte[] subkey = KeyDerivation.Pbkdf2(password, salt, Pbkdf2Prf, Pbkdf2IterCount, Pbkdf2SubkeyLength);

            var outputBytes = new byte[1 + SaltSize + Pbkdf2SubkeyLength];
            outputBytes[0] = 0x00; // format marker
            Buffer.BlockCopy(salt, 0, outputBytes, 1, SaltSize);
            Buffer.BlockCopy(subkey, 0, outputBytes, 1 + SaltSize, Pbkdf2SubkeyLength);
            return outputBytes;
        }

        public virtual bool VerifyHashedPasswordV2(byte[] hashedPassword, string password)
        {
            const KeyDerivationPrf Pbkdf2Prf = KeyDerivationPrf.HMACSHA1; // default for Rfc2898DeriveBytes
            const int Pbkdf2IterCount = 1000; // default for Rfc2898DeriveBytes
            const int Pbkdf2SubkeyLength = 256 / 8; // 256 bits
            const int SaltSize = 128 / 8; // 128 bits

            // We know ahead of time the exact length of a valid hashed password payload.
            if (hashedPassword.Length != 1 + SaltSize + Pbkdf2SubkeyLength)
            {
                return false; // bad size
            }

            byte[] salt = new byte[SaltSize];
            Buffer.BlockCopy(hashedPassword, 1, salt, 0, salt.Length);

            byte[] expectedSubkey = new byte[Pbkdf2SubkeyLength];
            Buffer.BlockCopy(hashedPassword, 1 + salt.Length, expectedSubkey, 0, expectedSubkey.Length);

            // Hash the incoming password and verify it
            byte[] actualSubkey = KeyDerivation.Pbkdf2(password, salt, Pbkdf2Prf, Pbkdf2IterCount, Pbkdf2SubkeyLength);

            return CryptographicOperations.FixedTimeEquals(actualSubkey, expectedSubkey);

        }

        public PasswordValidatorResponseDTO PasswordValidator(string password, int lengthMin, int lengthMax, int? lowerCase, int? upperCase, int? symbols, int? digit)
        {

            var response = new PasswordValidatorResponseDTO { ListError = new List<PasswordValidatorFailedDTO>(), Result = false };


            if (password.Any(Char.IsWhiteSpace))
            {
                response.Result = true;
                response.ListError.Add(
               new PasswordValidatorFailedDTO
               {
                   Arguments = $" ",
                   Message = $"A senha não pode conter espaço em branco"
               });
            }

            if (password.Count() < lengthMin || password.Count() > lengthMax)
            {
                response.Result = true;
                response.ListError.Add(
               new PasswordValidatorFailedDTO
               {
                   Arguments = $"{lengthMin} a {lengthMax}",
                   Message = $"A senha deve ter pelo menos {lengthMin} a {lengthMax} caracteres"
               });
            }


            if (password.Count(Char.IsUpper) < upperCase)
            {
                response.Result = true;
                response.ListError.Add(
                new PasswordValidatorFailedDTO
                {
                    Arguments = $"{upperCase}",
                    Message = $"A senha deve ter pelo menos {upperCase} letra maiúscula('A' - 'Z')"
                });
            }


            if (password.Count(Char.IsLower) < lowerCase)
            {
                response.Result = true;
                response.ListError.Add(
                new PasswordValidatorFailedDTO
                {
                    Arguments = $"{lowerCase}",
                    Message = $"A senha deve ter pelo menos {lowerCase} letra minúscula('a' - 'z')"
                });
            }


            if (password.Count(Char.IsDigit) < digit)
            {
                response.Result = true;
                response.ListError.Add(
                new PasswordValidatorFailedDTO
                {
                    Arguments = $"{digit}",
                    Message = $"A senha deve ter pelo menos {digit} dígito('0' - '9')"
                });
            }


            if (password.Count(x => !Char.IsLetterOrDigit(x)) < symbols)
            {
                response.Result = true;
                response.ListError.Add(
               new PasswordValidatorFailedDTO
               {
                   Arguments = $"{symbols}",
                   Message = $"A senha deve ter pelo menos {symbols} símbolo não alfanumérico"
               });
            }

            if (response.ListError.Count() == 0)
            {
                response.Result = false;
            }


            return response;
        }
    }
}
