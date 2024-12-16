using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace CoreSaml2Utils
{
    public class LogoutResponse : RequestBase
    {
        private readonly string _inResponseToId;
        private readonly string _status;

        public LogoutResponse(
            string issuer,
            string inResponseToId,
            string status = "urn:oasis:names:tc:SAML:2.0:status:Success",
            X509Certificate2 cert = null
        ) : base(
                 issuer,
                 null,
                 cert
                )
        {
            _inResponseToId = inResponseToId;
            _status = status;
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
                xmlWriter.WriteStartElement("samlp", "LogoutResponse", "urn:oasis:names:tc:SAML:2.0:protocol");
                xmlWriter.WriteAttributeString("ID", Id);
                xmlWriter.WriteAttributeString("Version", "2.0");
                xmlWriter.WriteAttributeString("IssueInstant", BuildIssueInstant());

                xmlWriter.WriteAttributeString("InResponseTo", _inResponseToId);

                xmlWriter.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                xmlWriter.WriteString(Issuer);
                xmlWriter.WriteEndElement();

                xmlWriter.WriteStartElement("saml", "Status", "urn:oasis:names:tc:SAML:2.0:assertion");
                
                xmlWriter.WriteStartElement("saml", "StatusCode", "urn:oasis:names:tc:SAML:2.0:assertion");
                xmlWriter.WriteAttributeString("Value", _status);
                xmlWriter.WriteEndElement();
                
                xmlWriter.WriteEndElement();

                xmlWriter.WriteEndElement();
            }

            return stringWriter.ToString();
        }
    }
}