using AuthJwtBearer.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthJwtBearer.DataBaseContext
{
    public class DataContext : DbContext
    {
        protected readonly IConfiguration _configuration;

        public DataContext(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            // Sqlite
            //options.UseSqlite(_configuration.GetConnectionString("SqliteConnection") ?? throw new InvalidOperationException("Connection string 'SqliteConnection' not found."));

            // SqlServer
            options.UseSqlServer(_configuration.GetConnectionString("SqlServerConnection") ?? throw new InvalidOperationException("Connection string 'SqlServerConnection' not found."));
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>().ToTable("Usuarios");
        }

        public DbSet<User> Usuarios { get; set; }
    }
}
