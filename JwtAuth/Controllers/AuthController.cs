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
        public ActionResult<User> Register(UserDto request) {
            var hashedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);
            user.Username = request.Username;
            user.PasswordHash = hashedPassword;
            return Ok(new { message="user registered succesfully",success=true,user });
        }

        [HttpPost("Login")]
        public ActionResult<string> Login(UserDto request) { 
            if(user.Username != request.Username)
            {
                return BadRequest(new { message = "User not found", success = false });
            }
            if( new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password)==PasswordVerificationResult.Failed){
                return BadRequest(new { message = "Invalid password", success = false });
            }

            string token = "success";

            return Ok(new { token, message = "Login successful", success = true });
        }
        
    }


}
