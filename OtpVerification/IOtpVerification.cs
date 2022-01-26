using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MhozaifaA.OtpVerification
{
    public interface IOtpVerification
    {
        OtpVia Generate(string id);
        OtpVia Generate(string id, out DateTime expire);
        OtpVia Generate(string id, OtpVerificationOptions option);
        OtpVia Generate(string id, OtpVerificationOptions option, out DateTime expire);
        bool Scan(string id, string plain);
        bool Scan(string id, string plain, OtpVerificationOptions option);
        bool Scan(string id, string plain, int expire);
        bool Scan(string url);
    }
}
