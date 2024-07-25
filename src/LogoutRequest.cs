using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace CoreSaml2Utils
{
    public class LogoutRequest : RequestBase
    {
        private readonly string _nameId;

        public LogoutRequest(
            string issuer,
            string requestDestination,
            string nameId,
            X509Certificate2 cert = null
        ) : base(
                 issuer,
                 requestDestination,
                 cert
                )
        {
            _nameId = nameId;
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
                xmlWriter.WriteStartElement("samlp", "LogoutRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
                xmlWriter.WriteAttributeString("ID", Id);
                xmlWriter.WriteAttributeString("Version", "2.0");
                xmlWriter.WriteAttributeString("IssueInstant", BuildIssueInstant());
                xmlWriter.WriteAttributeString("Destination", RequestDestination);

                xmlWriter.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                xmlWriter.WriteString(Issuer);
                xmlWriter.WriteEndElement();

                xmlWriter.WriteStartElement("saml", "NameID", "urn:oasis:names:tc:SAML:2.0:assertion");
                xmlWriter.WriteString(_nameId);
                xmlWriter.WriteEndElement();

                xmlWriter.WriteEndElement();
            }

            return stringWriter.ToString();
        }
    }
}