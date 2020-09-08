using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace CoreSaml2Utils
{
    public class AuthnRequestFactory
    {
        private readonly string _issuer;
        private readonly string _assertionConsumerServiceUrl;
        private readonly string _requestDestination;
        private readonly X509Certificate2 _cert;

        private readonly string _id;

        public AuthnRequestFactory(
                            string issuer,
                            string assertionConsumerServiceUrl,
                            string requestDestination,
                            X509Certificate2 cert = null
                        )
        {
            _issuer = issuer;
            _assertionConsumerServiceUrl = assertionConsumerServiceUrl;
            _requestDestination = requestDestination;
            _cert = cert;

            _id = $"_{Guid.NewGuid()}";
        }

        //returns the URL you should redirect your users to (i.e. your SAML-provider login URL with the Base64-ed request in the querystring
        public string GetRedirectUrl(string samlEndpoint, string relayState, bool sign)
        {
            var request = GetUnSignedRequest();

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

        private string GetUnSignedRequest()
        {
            var docString = BuildRequestXml();
            return Base64Encode(docString);
        }

        private string BuildRequestXml()
        {
            var xmlWriterSettings = new XmlWriterSettings
            {
                OmitXmlDeclaration = true
            };

            using var stringWriter = new StringWriter();
            using (var xmlWriter = XmlWriter.Create(stringWriter, xmlWriterSettings))
            {
                xmlWriter.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
                xmlWriter.WriteAttributeString("ID", _id);
                xmlWriter.WriteAttributeString("Version", "2.0");
                xmlWriter.WriteAttributeString("IssueInstant", DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture));
                xmlWriter.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
                xmlWriter.WriteAttributeString("AssertionConsumerServiceURL", _assertionConsumerServiceUrl);
                xmlWriter.WriteAttributeString("Destination", _requestDestination);

                xmlWriter.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                xmlWriter.WriteString(_issuer);
                xmlWriter.WriteEndElement();

                xmlWriter.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
                xmlWriter.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
                xmlWriter.WriteAttributeString("AllowCreate", "true");
                xmlWriter.WriteEndElement();

                /*xw.WriteStartElement("samlp", "RequestedAuthnContext", "urn:oasis:names:tc:SAML:2.0:protocol");
                xw.WriteAttributeString("Comparison", "exact");
                xw.WriteStartElement("saml", "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:assertion");
                xw.WriteString("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
                xw.WriteEndElement();
                xw.WriteEndElement();*/

                xmlWriter.WriteEndElement();
            }

            return stringWriter.ToString();
        }

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