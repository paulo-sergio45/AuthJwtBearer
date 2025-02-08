using AuthJwtBearer.DataBaseContext;
using AuthJwtBearer.DTOs;
using AuthJwtBearer.Entities;
using AuthJwtBearer.Interfaces;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace AuthJwtBearer.Repositories
{
    public class UserRepository(DataContext context, IPasswordHelper passwordHelper) : IUserRepository
    {

        private readonly DataContext _context = context;
        private readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();
        private readonly IPasswordHelper _passwordHelper = passwordHelper;

        public async Task<List<User>> GetUsuariosAsync()
        {
            return await _context.Usuarios.ToListAsync();
        }

        public async Task<User?> GetUsuarioByIdAsync(Guid usuarioId)
        {

            var usuario = await _context.Usuarios.FirstOrDefaultAsync(u => u.Id == usuarioId);

            if (usuario == null)
                return null;

            return usuario;
        }

        public async Task<User?> GetUsuarioByEmailAsync(string Email)
        {

            var usuario = await _context.Usuarios.FirstOrDefaultAsync(u => u.Email == Email);

            if (usuario == null)
                return null;

            return usuario;
        }

        public async Task<User?> LoginUsuarioAsync(UserLoginDTO usuarioLogin)
        {

            var usuario = await GetUsuarioByEmailAsync(usuarioLogin.Email);

            if (usuario == null || !usuario.EmailConfirmed)
                return null;

            byte[] decodedHashedPassword = Convert.FromBase64String(usuario.Password);

            var hashed = _passwordHelper.VerifyHashedPasswordV2(decodedHashedPassword, usuarioLogin.Password);

            if (!hashed)
                return null;

            return usuario;
        }

        public async Task<User> UpdateUsuarioAsync(User atualizarUsuario)
        {

            _context.Usuarios.Update(atualizarUsuario);
            await _context.SaveChangesAsync();

            return atualizarUsuario;
        }


        public async Task<bool> RecuperarSenhaUsuario(User senhaUsuario)
        {

            senhaUsuario.Password = Convert.ToBase64String(_passwordHelper.HashPasswordV2(senhaUsuario.Password, _rng));

            await UpdateUsuarioAsync(senhaUsuario);

            await _context.SaveChangesAsync();

            return true;
        }

        public async Task<User> DeleteUsuarioAsync(User excluirUsuario)
        {
            excluirUsuario.IsActive = false;
            await UpdateUsuarioAsync(excluirUsuario);

            return excluirUsuario;
        }

        public async Task<bool> ComfirmaEmailUsuarioAsync(string EmailUsuario)
        {
            var atualizarUsuario = await _context.Usuarios.FirstOrDefaultAsync(e => e.Email == EmailUsuario);

            if (atualizarUsuario == null)
                return false;

            atualizarUsuario.IsActive = true;
            atualizarUsuario.EmailConfirmed = true;

            await UpdateUsuarioAsync(atualizarUsuario);

            return true;
        }

        public async Task<User> AddUsuarioAsync(UserRequestDTO novoUsuario)
        {
            var senha = Convert.ToBase64String(_passwordHelper.HashPasswordV2(novoUsuario.Password, _rng));

            User usuario = new()
            {
                Id = Guid.NewGuid(),
                UserName = novoUsuario.UserName,
                Password = senha,
                UserType = UserTypes.User,
                Email = novoUsuario.Email,
                EmailConfirmed = false,
                IsActive = false
            };

            await _context.Usuarios.AddAsync(usuario);
            await _context.SaveChangesAsync();

            return usuario;
        }

        public async Task<bool> ExistsUsuarioAsync(string usuarioExists)
        {
            return await _context.Usuarios.AnyAsync(e => e.Email == usuarioExists);
        }




    }
}
