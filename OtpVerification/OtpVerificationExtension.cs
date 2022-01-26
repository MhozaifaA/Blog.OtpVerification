using MhozaifaA.OtpVerification.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MhozaifaA.OtpVerification
{
    public class OtpVerificationExtension : SecureHasher
    {
        public static string Generate(OtpVerificationOptions option, out DateTime expire, out string hash)
        {
            if (option is null)
                throw new ArgumentNullException($"{nameof(OtpVerification)} {nameof(option)} can't be null");

            if (option.Size <= 0)
                throw new ArgumentException($"{nameof(OtpVerification)} {nameof(option.Size)} can't be 0 or low");

            if (option.Length <= 0)
                throw new ArgumentException($"{nameof(OtpVerification)} {nameof(option.Length)} can't be 0 or low");

            if (option.Expire < 0)
                throw new ArgumentException($"{nameof(OtpVerification)} {nameof(option.Expire)} can't be low than 0");

            if (option.Iterations <= 0)
                throw new ArgumentException($"{nameof(OtpVerification)} {nameof(option.Iterations)} can't be 0 or low");

            DateTime dateNow = DateTime.Now;
            string plain = Generator.RandomString(option.Size,StringsOfLetters.Number);
            expire = dateNow.AddSeconds(59 - dateNow.Second).AddMinutes(option.Expire - 1);
            hash = Hash(plain + dateNow.ToString("yyyyMMddHHmm"), option.Length, option.Iterations);
            return plain;
        }

        public static string Generate(out DateTime expire, out string hash)
        {
            return Generate(new OtpVerificationOptions(), out expire, out hash);
        }

        public static string Generate(OtpVerificationOptions option, out string hash)
        {
            return Generate(option, out _, out hash);
        }

        public static string Generate(out string hash)
        {
            return Generate(new OtpVerificationOptions(), out hash);
        }

        public static string Generate(OtpVerificationOptions option, out DateTime expire)
        {
            return Generate(option, out expire, out _);
        }

        public static string Generate(out DateTime expire)
        {
            return Generate(new OtpVerificationOptions(), out expire);
        }

        public static string Generate(OtpVerificationOptions option)
        {
            return Generate(option, out _, out _);
        }

        public static string Generate()
        {
            return Generate(new OtpVerificationOptions());
        }


        public static bool Scan(string plain, string hash, OtpVerificationOptions option)
        {
            if (string.IsNullOrEmpty(plain))
                throw new ArgumentNullException($"{nameof(OtpVerification)} {nameof(plain)} can't be null or empty");

            if (string.IsNullOrEmpty(hash))
                throw new ArgumentNullException($"{nameof(OtpVerification)} {nameof(hash)} can't be null or empty");

            bool verify;
            int begin = 0;
            do
            {
                verify = Verify(plain + DateTime.Now.AddMinutes(-begin).ToString("yyyyMMddHHmm"), hash);
                begin++;
            } while (verify == false && begin <= option.Expire);

            return verify;
        }

        public static bool Scan(string plain, string hash, int expire)
        {
            return Scan(plain, hash, new OtpVerificationOptions() { Expire = expire });
        }

        public static bool Scan(string plain, string hash)
        {
            return Scan(plain, hash, new OtpVerificationOptions());
        }

    }
}
