using AuthJwtBearer.Entities;
using AuthJwtBearer.Interfaces;
using AuthJwtBearer.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthJwtBearer.Services
{
    public class TokenService(IConfiguration configuration) : ITokenService
    {
        private readonly IConfiguration _configuration = configuration;

        public string GenerateToken(User usuario)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["JwtSettings:JwtKey"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, usuario.Id.ToString()),
                    new Claim(ClaimTypes.Name, usuario.UserName.ToString()),
                    new Claim(ClaimTypes.Role, usuario.UserType.ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Audience = _configuration["JwtSettings:JwtAudience"],
                Issuer = _configuration["JwtSettings:JwtIssuer"],
                TokenType = "jwt + access"
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }



        public string GenerateTokenConfirmation(User usuario, TokenModel typeToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = SelectTypeToken(typeToken);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, usuario.Id.ToString()),
                    new Claim(ClaimTypes.Name, usuario.UserName.ToString()),
                }),
                Expires = DateTime.UtcNow.AddMinutes(20),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Audience = _configuration["JwtSettings:JwtAudience"],
                Issuer = _configuration["JwtSettings:JwtIssuer"]

            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }


        public string? TokenValidate(string token, TokenModel typeToken)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();

                var key = SelectTypeToken(typeToken);

                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = false,

                    ValidIssuer = _configuration["JwtSettings:JwtIssuer"],
                    ValidAudience = _configuration["JwtSettings:JwtAudience"],

                };

                tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken jwt);
                var payload = tokenHandler.ReadJwtToken(token).Payload.ToDictionary(kvp => kvp.Key);

                return (string)payload["nameid"].Value;
            }
            catch (Exception ex)
            {
                return null;
            }


        }

        private byte[]? SelectTypeToken(TokenModel typeToken)
        {

            switch (typeToken)
            {
                case TokenModel.RefreshToken:
                    return Encoding.ASCII.GetBytes(_configuration["JwtSettings:JwtKeyRefreshConfirmation"]);


                case TokenModel.ConfirmEmailToken:
                    return Encoding.ASCII.GetBytes(_configuration["JwtSettings:JwtKeyEmailConfirmation"]);


                case TokenModel.RecoverPasswordToken:
                    return Encoding.ASCII.GetBytes(_configuration["JwtSettings:JwtKeyPasswordConfirmation"]);


                default:
                    return [];

            }

        }
    }
}
