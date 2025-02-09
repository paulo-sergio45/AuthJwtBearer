using AuthJwtBearer.DTOs;
using AuthJwtBearer.Entities;

namespace AuthJwtBearer.Interfaces
{
    public interface IUserRepository
    {
        Task<List<User>> GetUsuariosAsync(int pagina, int size);

        Task<User?> GetUsuarioByEmailAsync(string Email);

        Task<User?> GetUsuarioByIdAsync(Guid usuarioId);

        Task<User?> LoginUsuarioAsync(UserLoginDTO usuarioLogin);

        Task<User> AddUsuarioAsync(UserRequestDTO usuario);

        Task<User> UpdateUsuarioAsync(User usuario);

        Task<User> DeleteUsuarioAsync(User usuario);

        Task<bool> ExistsUsuarioAsync(string Email);

        Task<bool> ComfirmaEmailUsuarioAsync(string EmailUsuario);

        Task<bool> RecuperarSenhaUsuario(User senhaUsuario);
    }
}
