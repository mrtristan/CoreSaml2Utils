using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using CoreSaml2Utils.Utilities;

namespace CoreSaml2Utils
{
    public abstract class RequestBase
    {
        protected readonly string Id;
        protected readonly string Issuer;
        protected readonly string RequestDestination;
        private readonly X509Certificate2 _cert;

        protected RequestBase(
            string issuer,
            string requestDestination,
            X509Certificate2 cert = null
        )
        {
            Issuer = issuer;
            RequestDestination = requestDestination;
            _cert = cert;
            Id = $"_{Guid.NewGuid()}";
        }

        //returns the URL you should redirect your users to (i.e. your SAML-provider login URL with the Base64-ed request in the querystring
        public string GetRedirectUrl(string samlEndpoint, string relayState, bool sign)
        {
            var xml = BuildRequestXml();
            var request = Base64Encode(xml);

            //http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
            //this exact format matters per 3.4.4.1 of https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
            var urlParams = $"SAMLRequest={Uri.EscapeDataString(request)}";

            //RelayState param must not be present if empty
            if (!string.IsNullOrEmpty(relayState))
            {
                urlParams = $"{urlParams}&RelayState={Uri.EscapeDataString(relayState)}";
            }

            if (sign)
            {
                if (_cert == null)
                {
                    throw new ArgumentNullException("Missing certificate");
                }

                urlParams = $"{urlParams}&SigAlg={Uri.EscapeDataString("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")}";

                using var rsa = _cert.GetRSAPrivateKey();
                var signature = rsa.SignData(Encoding.UTF8.GetBytes(urlParams), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                urlParams = $"{urlParams}&Signature={Uri.EscapeDataString(Convert.ToBase64String(signature))}";
            }

            var queryStringSeparator = samlEndpoint.Contains("?") ? "&" : "?";
            return $"{samlEndpoint}{queryStringSeparator}{urlParams}";
        }

        public string BuildRequestBody(bool sign)
        {
            var xml = BuildRequestXml();

            var xmlDocument = new XmlDocument();
            xmlDocument.LoadXml(xml);

            if (sign)
            {
                var signedXml = SigningHelper.SignXml(xmlDocument, _cert, "ID", Id);
                xmlDocument.DocumentElement?.InsertBefore(
                                                          signedXml.GetXml(),
                                                          xmlDocument.DocumentElement.ChildNodes[0]
                                                         );
            }

            return xmlDocument.OuterXml;
        }

        protected abstract string BuildRequestXml();

        protected static string BuildIssueInstant()
            => DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture);

        private string Base64Encode(string input)
        {
            //byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(sw.ToString());
            //return System.Convert.ToBase64String(toEncodeAsBytes);

            //https://stackoverflow.com/questions/25120025/acs75005-the-request-is-not-a-valid-saml2-protocol-message-is-showing-always%3C/a%3E
            var memoryStream = new MemoryStream();
            var writer = new StreamWriter(new DeflateStream(memoryStream, CompressionMode.Compress, true), new UTF8Encoding(false));
            writer.Write(input);
            writer.Close();
            return Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length, Base64FormattingOptions.None);
        }
    }
}