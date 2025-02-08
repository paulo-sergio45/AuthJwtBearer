using AuthJwtBearer.DTOs;
using AuthJwtBearer.Interfaces;
using AuthJwtBearer.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace AuthJwtBearer.Controllers.v1
{
    [ApiController]

    [Route("v1/[controller]")]
    public class AuthController(ILogger<AuthController> logger, IUserRepository userRepository, ITokenService tokenService, IEmailService emailService) : ControllerBase
    {

        private readonly ILogger<AuthController> _logger = logger;
        private readonly IUserRepository _userRepository = userRepository;
        private readonly ITokenService _tokenService = tokenService;
        private readonly IEmailService _emailService = emailService;

        [HttpPost]
        [Route("login")]
        [AllowAnonymous]
        public async Task<ActionResult<UserResponseDTO>> Login([FromBody] UserLoginDTO usuarioLogin)
        {
            try
            {
                var usuarioLogado = await _userRepository.LoginUsuarioAsync(usuarioLogin);

                if (usuarioLogado == null)
                    return Unauthorized(new { message = "Usuário ou senha inválidos" });

                var token = _tokenService.GenerateToken(usuarioLogado);
                var refreshToken = _tokenService.GenerateTokenConfirmation(usuarioLogado, TokenModel.RefreshToken);

                return Ok(new
                {
                    message = "Sucesso ao logar",
                    usuario = new UserResponseDTO()
                    {
                        Id = usuarioLogado.Id,
                        Email = usuarioLogado.Email,
                        UserName = usuarioLogado.UserName
                    },
                    token,
                    refreshToken
                });
            }
            catch (Exception ex)
            {
                _logger.LogError("Erro AuthenticateController : {ex}", ex);
                return StatusCode(500);
            }
        }

        [HttpGet]
        [Route("recover-password")]
        [AllowAnonymous]
        public async Task<ActionResult<UserResponseDTO>> SendEmailRecoverPassword([FromQuery] string email)
        {
            try
            {
                var usuarioExiste = await _userRepository.GetUsuarioByEmailAsync(email);

                if (usuarioExiste == null)
                    return Unauthorized();

                var tokenPasswordConfirmation = _tokenService.GenerateTokenConfirmation(usuarioExiste, TokenModel.RecoverPasswordToken);

                var callBackUrl = $"https://urlrecuperacaodesenha?tokenPasswordConfirmation={tokenPasswordConfirmation}";

                var emailBody = $"Clique no link a seguir para redefinir sua senha: {Environment.NewLine} <a href=\"{HtmlEncoder.Default.Encode(callBackUrl)}\">Clique Aqui</a>";


                var emaildata = new EmailModel()
                {
                    ToAddress = usuarioExiste.Email,
                    Name = usuarioExiste.UserName,
                    Subject = $"{usuarioExiste.UserName} Solicitação de Redefinição de Senha",
                    AttachmentPath = "",
                    Body = emailBody
                };

                await _emailService.Send(emaildata);

                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError("Erro AuthenticateController : {ex}", ex);
                return StatusCode(500);
            }
        }

        [HttpPost]
        [Route("reset-password")]
        [AllowAnonymous]
        public async Task<ActionResult> ResetPassword([FromBody] TokenDTOs tokenPasswordConfirmation)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(tokenPasswordConfirmation.Token))
                    return BadRequest(new { message = "Token não é valido" });

                var usuarioId = _tokenService.TokenValidate(tokenPasswordConfirmation.Token, TokenModel.RecoverPasswordToken);

                if (usuarioId == null)
                    return Unauthorized();

                if (!Guid.TryParse(usuarioId, out var guid))
                {
                    return BadRequest(new { message = "ID não é valido" });
                }

                var usuarioEncontrado = await _userRepository.GetUsuarioByIdAsync(guid);

                if (usuarioEncontrado == null)
                    return Unauthorized();

                var senhaAlterada = await _userRepository.RecuperarSenhaUsuario(usuarioEncontrado);

                if (!senhaAlterada)
                    return Unauthorized();

                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError("Erro AuthenticateController : {ex}", ex);
                return StatusCode(500);
            }
        }

        [HttpGet]
        [Route("confirm-email")]
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail([FromQuery] string tokenEmailConfirmation)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(tokenEmailConfirmation))
                    return BadRequest(new { message = "Token não é valido" });

                var usuarioId = _tokenService.TokenValidate(tokenEmailConfirmation, TokenModel.ConfirmEmailToken);

                if (usuarioId == null)
                    return Unauthorized();

                if (!Guid.TryParse(usuarioId, out var guid))
                {
                    return BadRequest(new { message = "ID não é valido" });
                }

                var usuarioEncontrado = await _userRepository.GetUsuarioByIdAsync(guid);

                if (usuarioEncontrado == null)
                    return Unauthorized();

                var emailConfirmado = await _userRepository.ComfirmaEmailUsuarioAsync(usuarioEncontrado.Email);

                if (!emailConfirmado)
                    return Unauthorized();

                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError("Erro AuthenticateController : {ex}", ex);
                return StatusCode(500);
            }
        }

        [HttpPost]
        [Route("refresh-token")]
        [AllowAnonymous]
        public async Task<ActionResult<UserResponseDTO>> RefreshToken([FromBody] TokenDTOs tokenRefreshConfirmation)
        {

            try
            {
                if (tokenRefreshConfirmation == null)
                    return BadRequest(new { message = "Token não é valido" });

                var usuarioId = _tokenService.TokenValidate(tokenRefreshConfirmation.Token, TokenModel.RefreshToken);

                if (usuarioId == null)
                    return Unauthorized();

                if (!Guid.TryParse(usuarioId, out var guid))
                {
                    return BadRequest(new { message = "ID não é valido" });
                }

                var usuarioEncontrado = await _userRepository.GetUsuarioByIdAsync(guid);

                if (usuarioEncontrado == null)
                    return Unauthorized();

                var token = _tokenService.GenerateToken(usuarioEncontrado);

                var refreshToken = _tokenService.GenerateTokenConfirmation(usuarioEncontrado, TokenModel.RefreshToken);

                return Ok(new
                {
                    message = "Sucesso ao Atualizar o token",
                    token,
                    refreshToken
                });
            }
            catch (Exception ex)
            {
                _logger.LogError("Erro AuthenticateController : {ex}", ex);
                return StatusCode(500);
            }
        }
    }
}

