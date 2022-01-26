using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MhozaifaA.OtpVerification
{
    public class OtpVerificationOptions
    {
        /// <summary>
        /// Enable or disable in-memory cache
        /// <para>Note: when enable in-memory will disable default cache (redis) </para>
        /// <para>default value: <see langword="false"/> (reids) will handle caching </para>
        /// </summary>
        internal bool IsInMemoryCache { get; set; } = false;

        /// <summary>
        /// Active to generate URL to verify code with Id OTP
        /// </summary>
        public bool EnableUrl { get; set; } = true;

        /// <summary>
        /// Number of complexity of rounds hashing.
        /// <para>Default value 1</para>
        /// </summary>
        public int Iterations { get; set; } = 1;

        /// <summary>
        /// Number of char code generator to hash.
        /// <para>Default value 6</para>
        /// </summary>
        public int Size { get; set; } = 6;

        /// <summary>
        /// Length hash result.
        /// <para>Default value 20</para>
        /// </summary>
        public int Length { get; set; } = 20;


        /// <summary>
        /// Measure after minutes.
        /// <para>Default value 2</para>
        /// </summary>
        public int Expire { get; set; } = 2;
    }
}
