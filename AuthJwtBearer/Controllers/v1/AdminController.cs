using AuthJwtBearer.DTOs;
using AuthJwtBearer.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthJwtBearer.Controllers.v1
{
    [ApiController]
    [Route("v1/[controller]")]
    public class AdminController(ILogger<AdminController> logger, IUserRepository userRepository) : ControllerBase
    {

        private readonly ILogger<AdminController> _logger = logger;
        private readonly IUserRepository _userRepository = userRepository;

        [HttpGet]
        [Route("GetUser")]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult> GetUser([FromQuery] string id)
        {
            try
            {

                if (!Guid.TryParse(id, out var guid))
                {
                    return BadRequest(new { message = "ID não é valido" });
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

        [HttpGet]
        [Route("GetUsers")]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<List<UserResponseDTO>>> GetUsers([FromQuery] int pagina, int size)
        {
            try
            {
                var usuarioEncontrado = await _userRepository.GetUsuariosAsync(pagina, size);

                var usuario = usuarioEncontrado.ConvertAll(x => new UserResponseDTO()
                {
                    Id = x.Id,
                    Email = x.Email,
                    UserName = x.UserName
                });

                return Ok(new
                {
                    message = "Sucesso ao encontrar Usuários",
                    usuario
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
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<UserResponseDTO>> PutUser([FromBody] UserRequestUpdateDTO usuario)
        {
            try
            {
                //var NameIdentifier = User.FindFirstValue(ClaimTypes.NameIdentifier);
                //var Role = User.FindFirstValue(ClaimTypes.Role);

                var usuarioOld = await _userRepository.GetUsuarioByEmailAsync(usuario.Email);

                if (usuarioOld == null)
                    return BadRequest(new { message = "Usuário não cadastrado" });


                usuarioOld.UserName = usuario.UserName;

                usuarioOld.UserType = usuario.UserType;

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
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult> DeleteUser([FromQuery] string id)
        {
            try
            {

                if (!Guid.TryParse(id, out var guid))
                {
                    return BadRequest(new { message = "ID não é valido" });
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
