using JwtAuth.Entities;
using JwtAuth.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new();
        [HttpPost("register")]
        public ActionResult<User> RegisterUser(UserDto request) {
            var hashedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);
            user.Username = request.Username;
            user.PasswordHash = hashedPassword;
            return Ok(new { message="user registered succesfully",success=true,user });
        }
    }
}
