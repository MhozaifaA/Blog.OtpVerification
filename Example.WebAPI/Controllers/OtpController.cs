using MhozaifaA.OtpVerification;
using MhozaifaA.OtpVerification.Utils;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace Example.WebAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]/[Action]")]
    public class OtpController : ControllerBase
    {
        private readonly IOtpVerification otp;
        public record class User(string FullName)
        {
            public int Id { get; set; }
            public bool isVerify { get; set; }
        };

        public static List<User> users = new List<User>();

        public OtpController(IOtpVerification otp)
        {
            this.otp = otp;
        }



        [HttpGet]
        public IActionResult GetUsers()
        {
            return Ok(users);
        }

        [HttpPost]
        public IActionResult CreateUser(User user)
        {
            user.isVerify = default;
            user.Id =int.Parse(Generator.RandomString(2,StringsOfLetters.Number));
            users.Add(user);

            var code = otp.Generate(user.Id.ToString(),expire: out DateTime expierDate);
            // this code sent by Email or SMS
            return Ok($"Your via is: {code} ,\nwill expire at: {expierDate}");
        }

        [HttpPost("{id}")]
        public IActionResult RefreshUser([FromRoute]int id)
        {
            var user = users.Where(u => u.Id == id).FirstOrDefault();
            if (user is null) return NotFound($"user with Id:{id} not exist");
            user.isVerify = false;
            var code = otp.Generate(user.Id.ToString(), expire: out DateTime expierDate);
            // this code sent by Email or SMS
            return Ok($"Your via is: {code} ,\nwill expire at: {expierDate}");
        }


        [HttpPost]
        public IActionResult VerifyUser([Range(0,99)] int userId,[Required] string code)
        {

            var one = users.Where(u => u.Id == userId).FirstOrDefault();
            if (one is null) return NotFound($"user with Id:{userId} not exist");

            if (one.isVerify) return BadRequest($"user with Id:{userId} is already verified");

            if(otp.Scan(userId.ToString(), code))
            {
                one.isVerify = true;
                return Ok($"user with Id:{userId} successful confirmed his OTP code {code}");
            }

            return BadRequest($"user with Id:{userId} enter wrong code or expired");
        }

    }
}
