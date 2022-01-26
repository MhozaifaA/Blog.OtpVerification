using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MhozaifaA.OtpVerification
{
    public struct OtpVia
    {
        //no need after C# 10
        public OtpVia(string code, string url = default)
        {
            Code = code;
            Url = url;
        }

        public string Code { get; set; }

        public string Url { get; set; }

        public override string ToString()
        {
            return $"Code:{Code}, Url:{Url}";
        }
    }
}
