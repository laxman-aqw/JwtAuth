using JwtAuth.Entities;
using JwtAuth.Models;
using JwtAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        public static User user = new();

        private readonly IAuthService _authService;
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request) {
           var user =  await _authService.RegisterAsync(request);
            if(user == null)
            {
                return BadRequest(new { message = "User already exists", success = false });
            }
            return Ok(new { message="user registered succesfully",success=true,user });
        }

        [HttpPost("Login")]
        public async Task<ActionResult<string>> Login(UserDto request) {
            var token = await _authService.LoginAsync(request);
            if(token == null)
            {
                return BadRequest(new { message="invalid username or password", success=false });
            }

            return Ok(new { token, message = "Login successful", success = true });
        }

        [Authorize]
        [HttpGet]
        public IActionResult AuthenticatedOnlyEndPoint() { 
            return Ok(new { message = "You are authenticated", success = true });
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin")]
        public IActionResult AdminOnlyEndPoint()
        {
            return Ok(new { message = "You are an admin", success = true });
        }

    }


}
