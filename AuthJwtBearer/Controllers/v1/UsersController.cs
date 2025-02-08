using AuthJwtBearer.DTOs;
using AuthJwtBearer.Interfaces;
using AuthJwtBearer.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace AuthJwtBearer.Controllers.v1
{

    [ApiController]
    [Route("v1/[controller]")]
    public class UsersController(ILogger<UsersController> logger, IUserRepository userRepository, IPasswordHelper passwordHelper, IEmailService emailService, ITokenService tokenService) : ControllerBase
    {
        private readonly ILogger<UsersController> _logger = logger;
        private readonly IUserRepository _userRepository = userRepository;
        private readonly IPasswordHelper _passwordHelper = passwordHelper;
        private readonly IEmailService _emailService = emailService;
        private readonly ITokenService _tokenService = tokenService;

        [HttpPost]
        [Route("PostUser")]
        [AllowAnonymous]

        public async Task<ActionResult> PostUser([FromBody] UserRequestDTO model)
        {
            try
            {
                var passwordValidator = _passwordHelper.PasswordValidator(model.Password, 8, 50, 2, 2, 2, 1);

                if (passwordValidator.Result)
                    return BadRequest(new
                    { passwordValidator = passwordValidator.ListError });


                var usuarioExists = await _userRepository.ExistsUsuarioAsync(model.Email);

                if (usuarioExists)
                    return BadRequest(new { message = "Usuário ja cadastrado" });

                var usuariocriado = await _userRepository.AddUsuarioAsync(model);

                if (usuariocriado == null)
                    return NotFound(new { message = "Dados de Usuário inválidos" });


                var tokenEmailConfirmation = _tokenService.GenerateTokenConfirmation(usuariocriado, TokenModel.ConfirmEmailToken);

                //so com biblioteca para usar url no C#

                var callBackUrl = $"https://localhost:44356/v1/Auth/confirm-email?tokenEmailConfirmation={tokenEmailConfirmation}";

                var emailBody = $"Por favor, confirme o email clicando neste link.{Environment.NewLine} <a href=\"{HtmlEncoder.Default.Encode(callBackUrl)}\">Clique Aqui</a>";

                var emaildata = new EmailModel()
                {
                    ToAddress = usuariocriado.Email,
                    Name = usuariocriado.UserName,
                    Subject = $"{usuariocriado.UserName} Confirme seu e-mail",
                    AttachmentPath = "",
                    Body = emailBody
                };

                await _emailService.Send(emaildata);

                //var serdEmail =
                return Created("Sucesso ao criar Usuário", new
                {
                    message = "Sucesso ao criar Usuário",
                    usuario = new UserResponseDTO()
                    {
                        Id = usuariocriado.Id,
                        Email = usuariocriado.Email,
                        UserName = usuariocriado.UserName
                    },
                });
            }
            catch (Exception ex)
            {
                _logger.LogError("Erro UsuarioController : {ex}", ex);
                return StatusCode(500);
            }
        }

        [HttpGet]
        [Route("GetUser")]
        [Authorize(Roles = "User")]
        public async Task<ActionResult> GetUser([FromQuery] string id)
        {
            try
            {

                if (!Guid.TryParse(id, out var guid))
                {
                    return BadRequest(new { message = "ID não é valido" });
                }

                if (Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var guidClaim))
                {
                    if (guid != guidClaim)
                        return Unauthorized();
                }

                var usuarioEncontrado = await _userRepository.GetUsuarioByIdAsync(guid);

                if (usuarioEncontrado == null)
                    return NotFound(new { message = "Usuário não encontrado" });

                return Ok(new
                {
                    message = "Sucesso ao encontrar Usuário",
                    usuario = new UserResponseDTO()
                    {
                        Id = usuarioEncontrado.Id,
                        Email = usuarioEncontrado.Email,
                        UserName = usuarioEncontrado.UserName
                    },
                });
            }
            catch (Exception ex)
            {
                _logger.LogError("Erro UsuarioController : {ex}", ex);
                return StatusCode(500);
            }
        }



        [HttpPut]
        [Route("PutUser")]
        [Authorize(Roles = "User")]
        public async Task<ActionResult<UserResponseDTO>> PutUser([FromBody] UserRequestUpdateDTO usuario)
        {
            try
            {

                if (Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var guidClaim))
                {
                    if (usuario.Id != guidClaim)
                        return Unauthorized();
                }

                var usuarioOld = await _userRepository.GetUsuarioByEmailAsync(usuario.Email);

                if (usuarioOld == null)
                    return BadRequest(new { message = "Usuário não cadastrado" });


                usuarioOld.UserName = usuario.UserName;
                usuarioOld.Password = usuario.Password;
                usuarioOld.Email = usuario.Email;

                var usuarioAtualizado = await _userRepository.UpdateUsuarioAsync(usuarioOld);

                if (usuarioAtualizado == null)
                    return BadRequest(new { message = "Erro ao atualizar Usuário" });

                return Ok(new
                {
                    message = "Sucesso ao atualizar Usuário",
                    usuario = new UserResponseDTO()
                    {
                        Id = usuarioAtualizado.Id,
                        Email = usuarioAtualizado.Email,
                        UserName = usuarioAtualizado.UserName
                    },
                });
            }
            catch (Exception ex)
            {
                _logger.LogError("Erro UsuarioController : {ex}", ex);
                return StatusCode(500);
            }
        }

        [HttpDelete]
        [Route("DeleteUser")]
        [Authorize(Roles = "User")]
        public async Task<ActionResult<UserResponseDTO>> DeleteUser([FromQuery] string id)
        {
            try
            {

                if (!Guid.TryParse(id, out var guid))
                {
                    return BadRequest(new { message = "ID não é valido" });
                }

                if (Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var guidClaim))
                {
                    if (guid != guidClaim)
                        return Unauthorized();
                }

                var usuarioEncontrado = await _userRepository.GetUsuarioByIdAsync(guid);

                if (usuarioEncontrado == null)
                    return NotFound(new { message = "Usuário não encontrado" });

                var usuarioDeletado = await _userRepository.DeleteUsuarioAsync(usuarioEncontrado);

                return Ok(new
                {
                    message = "Sucesso ao deletar Usuário",
                    usuario = new UserResponseDTO()
                    {
                        Id = usuarioDeletado.Id,
                        Email = usuarioDeletado.Email,
                        UserName = usuarioDeletado.UserName
                    },
                });
            }
            catch (Exception ex)
            {
                _logger.LogError("Erro UsuarioController : {ex}", ex);
                return StatusCode(500);
            }
        }
    }
}
