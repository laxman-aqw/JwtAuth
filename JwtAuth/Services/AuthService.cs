using JwtAuth.Entities;
using JwtAuth.Models;
using Microsoft.Extensions.Options;

namespace JwtAuth.Services
{
    public class AuthService : IAuthService
    {
        public AuthService(UserDbContext context, IConfiguration configuration) 
        { 
            
        }
        Task<string?> IAuthService.LoginAsync(UserDto request)
        {
            throw new NotImplementedException();
        }

        Task<User?> IAuthService.RegisterAsync(UserDto request)
        {
            throw new NotImplementedException();
        }
    }
}
