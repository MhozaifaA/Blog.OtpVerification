using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MhozaifaA.OtpVerification.Utils
{
    public abstract class SecureHasher
    {
        private const int SaltSize = 16;

        protected static string Hash(string plain, int hashSize, int iterations)
        {
            // Create salt
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] salt;
                rng.GetBytes(salt = new byte[SaltSize]);
                using (var pbkdf2 = new Rfc2898DeriveBytes(plain, salt, iterations))
                {
                    var hash = pbkdf2.GetBytes(hashSize);
                    // Combine salt and hash
                    var hashBytes = new byte[SaltSize + hashSize];
                    Array.Copy(salt, 0, hashBytes, 0, SaltSize);
                    Array.Copy(hash, 0, hashBytes, SaltSize, hashSize);
                    // Convert to base64
                    var base64Hash = Convert.ToBase64String(hashBytes);

                    // Format hash with extra information
                    return $"{iterations}${base64Hash}";
                }
            }

        }

        protected static bool Verify(string plain, string hashedPlain, int hashSize = 20)
        {

            // Extract iteration and Base64 string
            var splittedHashString = hashedPlain.Split('$');
            var iterations = int.Parse(splittedHashString[0]);
            var base64Hash = splittedHashString[1];

            // Get hash bytes
            var hashBytes = Convert.FromBase64String(base64Hash);

            // Get salt
            var salt = new byte[SaltSize];
            Array.Copy(hashBytes, 0, salt, 0, SaltSize);

            // Create hash with given salt
            using (var pbkdf2 = new Rfc2898DeriveBytes(plain, salt, iterations))
            {
                byte[] hash = pbkdf2.GetBytes(hashSize);

                // Get result
                for (var i = 0; i < hashSize; i++)
                {
                    if (hashBytes[i + SaltSize] != hash[i])
                    {
                        return false;
                    }
                }

                return true;
            }

        }
    }


    public class GeneratorOption
    {
        public GeneratorSize Size { get; set; }
        public GeneratoraCharacters Characters { get; set; }

        public GeneratorOption() { }

        public GeneratorOption(GeneratorSize size, GeneratoraCharacters characters)
        {
            Size = size;
            Characters = characters;
        }

        public static string GetCharacters(StringsOfLetters gcharacter)
        {
            switch (gcharacter)
            {
                case StringsOfLetters.Lower:
                    return "abcdefghijklmnopqrstuvwxyz";

                case StringsOfLetters.Upper:
                    return "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

                case StringsOfLetters.Number:
                    return "0123456789";

                case StringsOfLetters.Symbol:
                    return @"~!@#$%^&*()_-+=/\|.";

                case StringsOfLetters.Alphabet:
                    return "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";

                case StringsOfLetters.NumberAndLower:
                    return "0123456789abcdefghijklmnopqrstuvwxyz";

                case StringsOfLetters.NumberAndUpper:
                    return "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

                case StringsOfLetters.SymbolAndNumber:
                    return @"~!@#$%^&*()_-+=/\|.0123456789";

                case StringsOfLetters.SymbolAndNumberAndLower:
                    return @"~!@#$%^&*()_-+=/\|.0123456789abcdefghijklmnopqrstuvwxyz";

                case StringsOfLetters.SymbolAndNumberAndUpper:
                    return @"~!@#$%^&*()_-+=/\|.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

                case StringsOfLetters.NumberAndAlphabet:
                    return "0123456789AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";


                case StringsOfLetters.SymbolAndNumberAndAlphabet:
                    return @"~!@#$%^&*()_-+=/\|.0123456789AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";

                default:
                    return default;
            }
        }
    }

    public struct GeneratorSize
    {
        public int Value;//min
        private int _Max;

        public GeneratorSize(int value)
        {
            Value = value;
            _Max = value;
        }

        public GeneratorSize(int min, int max)
        {
            Value = min;
            _Max = max;
        }

        public int Max()
        {
            return _Max;
        }

        public static implicit operator GeneratorSize(int value)
        {
            return new GeneratorSize(value);
        }

        public static implicit operator int(GeneratorSize value)
        {
            return value.Value;
        }
    }

    public struct GeneratoraCharacters
    {
        public StringsOfLetters Value;
        private string _sequence;

        public GeneratoraCharacters(StringsOfLetters value)
        {
            Value = value;
            _sequence = default;
        }

        public GeneratoraCharacters(string sequence)
        {
            Value = default;
            _sequence = sequence;
        }

        public string Sequence()
        {
            return _sequence;
        }


        public static implicit operator GeneratoraCharacters(StringsOfLetters value)
        {
            return new GeneratoraCharacters(value);
        }

        public static implicit operator GeneratoraCharacters(string value)
        {
            return new GeneratoraCharacters(value);
        }
    }

    public enum StringsOfLetters : short
    {
        /// <summary>
        /// <![CDATA[ abcdefghijklmnopqrstuvwxyz  ]]> 
        /// </summary>
        Lower,
        /// <summary>
        /// <![CDATA[ ABCDEFGHIJKLMNOPQRSTUVWXYZ  ]]> 
        /// </summary>
        Upper,
        /// <summary>
        /// <![CDATA[ 0123456789  ]]>
        /// </summary>
        Number,
        /// <summary>
        /// <![CDATA[ ~!@#$%^&*()_-+=/\|. ]]>
        /// </summary>
        Symbol,
        /// <summary>
        /// <![CDATA[ AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz  ]]> 
        /// </summary>
        Alphabet,
        /// <summary>
        /// <![CDATA[ 0123456789abcdefghijklmnopqrstuvwxyz  ]]> 
        /// </summary>
        NumberAndLower,
        /// <summary>
        /// <![CDATA[ 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ  ]]> 
        /// </summary>
        NumberAndUpper,
        /// <summary>
        /// <![CDATA[ ~!@#$%^&*()_-+=/\|.0123456789  ]]> 
        /// </summary>
        SymbolAndNumber,
        /// <summary>
        /// <![CDATA[ ~!@#$%^&*()_-+=/\|.0123456789abcdefghijklmnopqrstuvwxyz  ]]> 
        /// </summary>
        SymbolAndNumberAndLower,
        /// <summary>
        /// <![CDATA[ ~!@#$%^&*()_-+=/\|.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ  ]]> 
        /// </summary>
        SymbolAndNumberAndUpper,
        /// <summary>
        /// <![CDATA[ 0123456789AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz  ]]> 
        /// </summary>
        NumberAndAlphabet,
        /// <summary>
        /// <![CDATA[ ~!@#$%^&*()_-+=/\|.0123456789AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz  ]]> 
        /// </summary>
        SymbolAndNumberAndAlphabet,
    }


    public class Generator
    {
        public static string RandomString(StringsOfLetters gCharacters = StringsOfLetters.NumberAndAlphabet)
        {
            return RandomString(new GeneratorOption(-1, gCharacters));
        }

        public static string RandomString(string characters)
        {
            return RandomString(new GeneratorOption(-1, characters));
        }

        public static string RandomString(int min, int max, StringsOfLetters gCharacters = StringsOfLetters.NumberAndAlphabet)
        {
            return RandomString(new GeneratorOption(new GeneratorSize(min, max), gCharacters));
        }

        public static string RandomString(int size, StringsOfLetters gCharacters = StringsOfLetters.NumberAndAlphabet)
        {
            return RandomString(new GeneratorOption(size, gCharacters));
        }

        public static string RandomString(int size, string characters)
        {
            return RandomString(new GeneratorOption(size, new GeneratoraCharacters(characters)));
        }

        public static string RandomString(GeneratorOption option)
        {
            char[] range = default;
            if (option.Characters.Sequence() == default)
                range = GeneratorOption.GetCharacters(option.Characters.Value).ToCharArray();
            if (option.Characters.Value == default)
                range = option.Characters.Sequence().ToCharArray();

            if (option.Size.Max() == option.Size)
                option.Size = new Random().Next(option.Size, option.Size.Max());
            if (option.Size < 0)
                option.Size = new Random().Next(4, 16);

            byte[] data = new byte[4 * option.Size];
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(data);
            }
            StringBuilder result = new StringBuilder(option.Size);
            for (int i = 0; i < option.Size; i++)
            {
                uint rnd = BitConverter.ToUInt32(data, i * 4);
                long idx = rnd % range.Length;
                result.Append(range[idx]);
            }
            return result.ToString();
        }
    }
}
