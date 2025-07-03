using JwtAuth.Entities;
using JwtAuth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuth.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserDbContext _context;
        private readonly IConfiguration _configuration;
        public AuthService(UserDbContext context, IConfiguration configuration) 
        {
            _context = context;
            _configuration = configuration;
            
        }
       public async Task<string?> LoginAsync(UserDto request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user == null) {
                return null;

            }
            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
            {
                return null;
            }


            return CreateToken(user);
        }

       public async Task<User?>RegisterAsync(UserDto request)
        {
            if (await _context.Users.AnyAsync(u => u.Username == request.Username)) {
                return null;
            }
            var user = new User();
            var hashedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);
            user.Username = request.Username;
            user.PasswordHash = hashedPassword;
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return user;
        }

        private string CreateToken(User user)
        {
            var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
    };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration["AppSettings:Token"]!));

            var secret = _configuration["AppSettings:Token"]!;
            var keyBytes = Encoding.UTF8.GetBytes(secret);
            Console.WriteLine($"Secret key length in bytes: {keyBytes.Length}");

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["AppSettings:Issuer"],
                audience: _configuration["AppSettings:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }
}
