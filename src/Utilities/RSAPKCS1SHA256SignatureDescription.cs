using System;
using System.Security.Cryptography;

namespace CoreSaml2Utils.Utilities
{
    /// <summary>
    /// this class adds support of SHA256 signing to .NET 4.0 and earlier
    /// (you can use it in .NET 4.5 too, if you don't want a "System.Deployment" dependency)
    /// </summary>
    public sealed class RSAPKCS1SHA256SignatureDescription : SignatureDescription
    {
        public RSAPKCS1SHA256SignatureDescription()
        {
            KeyAlgorithm = typeof(RSACryptoServiceProvider).FullName;
            DigestAlgorithm = typeof(SHA256Managed).FullName; // Note - SHA256CryptoServiceProvider is not registered with CryptoConfig
            FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).FullName;
            DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).FullName;
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var deformatter = new RSAPKCS1SignatureDeformatter(key);
            deformatter.SetHashAlgorithm("SHA256");
            return deformatter;
        }

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var formatter = new RSAPKCS1SignatureFormatter(key);
            formatter.SetHashAlgorithm("SHA256");
            return formatter;
        }

        private static bool _initialized;

        public static void Init()
        {
            if (!_initialized)
            {
                CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            }

            _initialized = true;
        }
    }
}