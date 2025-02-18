using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using ProductsAPI.DTO;
using ProductsAPI.Models;

namespace ProductsAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersControllers:ControllerBase
    {
        private readonly UserManager<AppUser> _userManager; // create user için
        private readonly SignInManager<AppUser> _signInManager; // sign in için

        private readonly IConfiguration _configuration; // Configurationa erişmek için development.json içinden key için JWT 


        public UsersControllers(UserManager<AppUser> userManager , SignInManager<AppUser> signInManager,IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> CreateUser(UserDTO model)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var user = new AppUser
            {
                FullName = model.FullName,
                UserName = model.UserName,
                Email = model.Email,
                DateAdded = DateTime.Now
            };
            var result = await _userManager.CreateAsync(user,model.Password);
            if(result.Succeeded)
            {
                return StatusCode(201);
            }
            return BadRequest(result.Errors);
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDTO model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if(user == null)
            {
                return BadRequest(new {messsage ="Email hatası"});
            }
            var result = await _signInManager.CheckPasswordSignInAsync(user,model.Password,false);
            if(result.Succeeded)
            {
                return Ok(new {token = GenerateJWT(user)});
            }
            return Unauthorized();
        }

        private object GenerateJWT(AppUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            //burda GetSection diyerek development.json a erişiyoruz ve bu keyi string olarak değil de byte olarak almak istediğimiz için dönüşümleri yapıyoruz.gelen key boşsa da boş string ver diyoruz
            var key = Encoding.ASCII.GetBytes(_configuration.GetSection("AppSettings:Secret").Value ?? "");

            var tokenDescriptor = new SecurityTokenDescriptor // tokenin özelliklerini veriyoruz
            {
                Subject = new ClaimsIdentity(
                new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier,user.Id.ToString()),
                    new Claim(ClaimTypes.Name, user.UserName ?? ""),
                }
            ),
            Expires = DateTime.UtcNow.AddDays(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),SecurityAlgorithms.HmacSha256Signature) // tokenin şifreleme algoritması
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token); // token string tipinde geriye döndürülüyor

        }
    }
}