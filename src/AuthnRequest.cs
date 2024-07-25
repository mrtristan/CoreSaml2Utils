using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace CoreSaml2Utils
{
    public class AuthnRequest : RequestBase
    {
        private readonly string _assertionConsumerServiceUrl;
        private readonly bool _forceAuthn;

        public AuthnRequest(
            string issuer,
            string assertionConsumerServiceUrl,
            string requestDestination,
            X509Certificate2 cert = null,
            bool forceAuthn = false
        ) : base(
                 issuer,
                 requestDestination,
                 cert
                )
        {
            _assertionConsumerServiceUrl = assertionConsumerServiceUrl;
            _forceAuthn = forceAuthn;
        }

        protected override string BuildRequestXml()
        {
            var xmlWriterSettings = new XmlWriterSettings
                                    {
                                        OmitXmlDeclaration = true
                                    };

            using var stringWriter = new StringWriter();
            using (var xmlWriter = XmlWriter.Create(stringWriter, xmlWriterSettings))
            {
                xmlWriter.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
                xmlWriter.WriteAttributeString("ID", Id);
                xmlWriter.WriteAttributeString("Version", "2.0");
                xmlWriter.WriteAttributeString("IssueInstant", BuildIssueInstant());
                xmlWriter.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
                xmlWriter.WriteAttributeString("AssertionConsumerServiceURL", _assertionConsumerServiceUrl);
                if (_forceAuthn)
                {
                    xmlWriter.WriteAttributeString("ForceAuthn", "true");
                }

                xmlWriter.WriteAttributeString("Destination", RequestDestination);

                xmlWriter.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                xmlWriter.WriteString(Issuer);
                xmlWriter.WriteEndElement();

                xmlWriter.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
                xmlWriter.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
                xmlWriter.WriteAttributeString("AllowCreate", "true");
                xmlWriter.WriteEndElement();
                xmlWriter.WriteEndElement();
            }

            return stringWriter.ToString();
        }
    }
}