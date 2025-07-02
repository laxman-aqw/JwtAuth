using JwtAuth.Entities;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography.X509Certificates;

namespace JwtAuth
{
    public class UserDbContext : DbContext
    {
        public UserDbContext(DbContextOptions<UserDbContext> options):base(options) { 
        }
            public DbSet<User> Users{ get; set; }

        
    }
}
