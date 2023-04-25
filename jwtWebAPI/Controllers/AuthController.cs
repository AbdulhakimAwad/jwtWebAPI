using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace jwtWebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configration;

        public AuthController(IConfiguration configration)
        {
            this._configration = configration;
        }
        [HttpPost("register")]
        public async Task<ActionResult<User>>Register(UserDTO req)
        {
            CreateHashPassword(req.Password,out byte[]passwordHash,out byte[]passwordSalt);
            user.UserName = req.USerName;
            user.PasswordSalt = passwordSalt;
            user.PasswordHash = passwordHash;

            return Ok(user);
        }
        [HttpPost("login")]
        public async Task<ActionResult<string>>Login(UserDTO req) 
        {
            //verify user name
            if (req.USerName != user.UserName)
            {
                return BadRequest("user is not exists");
            }


            //verify password
            if(!verifyPassword(req.Password,user.PasswordHash,user.PasswordSalt)) 
            {
                return BadRequest("Password is unCorrect");
            }
            var token = CreateToken(user);
            return Ok(token);
        }

        private string CreateToken(User user) 
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,user.UserName)
            };

            //get the secrit key
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configration.GetSection("AppSettings:Token").Value));

            //configure the credentials
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            // create the token
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials:cred);

            //get the jwt
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);


            return jwt;
        }
        private bool verifyPassword(string password, byte[] passWordHashed, byte[]passWordSalt) 
        {
            using(var hmac=new HMACSHA512(passWordSalt)) 
            {
                var ComputedHash=hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return ComputedHash.SequenceEqual(passWordHashed);
            }
        }

        //on production mode we should move this method from here to keep the controller clean
        private void CreateHashPassword(string password, out byte[] passwordHash,out byte[] passwordSalt) 
        {
            using(var hmac=new HMACSHA512()) 
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

    }
}
