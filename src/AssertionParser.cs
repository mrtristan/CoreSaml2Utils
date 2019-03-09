using CoreSaml2Utils.Utilities;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace CoreSaml2Utils
{
    public class AssertionParser
    {
        public AssertionParser()
        {
            RSAPKCS1SHA256SignatureDescription.Init(); //init the SHA256 crypto provider (for needed for .NET 4.0 and lower)
        }

        #region public methods

        public void LoadCertFromFile(string file)
        {
            _certificate = CertificateUtilities.LoadCertificateFile(file);
        }

        public void LoadCertBody(byte[] certificateBytes)
        {
            _certificate = CertificateUtilities.LoadCertificate(certificateBytes);
        }

        public void LoadCertBody(string certificateStr)
        {
            _certificate = CertificateUtilities.LoadCertificate(certificateStr);
        }

        public string Xml => _xmlDoc.OuterXml;

        public void LoadXml(string xml)
        {
            _xmlDoc = new XmlDocument
            {
                PreserveWhitespace = true,
                XmlResolver = null
            };
            _xmlDoc.LoadXml(xml);

            //returns namespace manager, we need one b/c MS says so... Otherwise XPath doesnt work in an XML doc with namespaces
            //see https://stackoverflow.com/questions/7178111/why-is-xmlnamespacemanager-necessary

            var namespaceManager = new XmlNamespaceManager(_xmlDoc.NameTable);
            namespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            namespaceManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            namespaceManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

            _xmlNameSpaceManager = namespaceManager;
        }

        public void LoadXmlFromBase64(string response)
        {
            var enc = new UTF8Encoding();
            var decoded = enc.GetString(Convert.FromBase64String(response));
            LoadXml(decoded);
        }

        public bool IsValid(string expectedAudience)
        {
            var nodeList = _xmlDoc.SelectNodes("//ds:Signature", _xmlNameSpaceManager);

            if (nodeList.Count == 0)
            {
                return false;
            }

            var signedXml = new SignedXml(_xmlDoc);
            signedXml.LoadXml((XmlElement)nodeList[0]);

            return ValidateSignatureReference(signedXml)
                    && signedXml.CheckSignature(_certificate, true)
                    && !IsExpired()
                    && IsExpectedAudience(expectedAudience);
        }

        public string GetNameID()
        {
            var node = _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertion}/saml:Subject/saml:NameID", _xmlNameSpaceManager);
            return node?.InnerText;
        }

        public string[] GetGroupSIDs()
        {
            var node = _xmlDoc.SelectNodes($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid']/saml:AttributeValue", _xmlNameSpaceManager);
            return node
                    ?.Cast<XmlNode>()
                    .Select(x => x?.InnerText)
                    .Where(x => x != null)
                    .ToArray();
        }

        public string GetEmail()
        {
            var node = _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='User.email']/saml:AttributeValue", _xmlNameSpaceManager)
                        ?? _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']/saml:AttributeValue", _xmlNameSpaceManager);

            return node?.InnerText;
        }

        public string GetFirstName()
        {
            var node = _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='first_name']/saml:AttributeValue", _xmlNameSpaceManager)
                        ?? _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname']/saml:AttributeValue", _xmlNameSpaceManager)
                        ?? _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='User.FirstName']/saml:AttributeValue", _xmlNameSpaceManager);

            return node?.InnerText;
        }

        public string GetLastName()
        {
            var node = _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='last_name']/saml:AttributeValue", _xmlNameSpaceManager)
                        ?? _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname']/saml:AttributeValue", _xmlNameSpaceManager)
                        ?? _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='User.LastName']/saml:AttributeValue", _xmlNameSpaceManager);

            return node?.InnerText;
        }

        public string GetDepartment()
        {
            var node = _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department']/saml:AttributeValue", _xmlNameSpaceManager);
            return node?.InnerText;
        }

        public string GetPhone()
        {
            var node = _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone']/saml:AttributeValue", _xmlNameSpaceManager)
                        ?? _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/telephonenumber']/saml:AttributeValue", _xmlNameSpaceManager);

            return node?.InnerText;
        }

        public string GetCompany()
        {
            var node = _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/companyname']/saml:AttributeValue", _xmlNameSpaceManager)
                        ?? _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='User.CompanyName']/saml:AttributeValue", _xmlNameSpaceManager);

            return node?.InnerText;
        }

        #endregion

        private XmlDocument _xmlDoc;
        private X509Certificate2 _certificate;
        private XmlNamespaceManager _xmlNameSpaceManager; //we need this one to run our XPath queries on the SAML XML

        //an XML signature can "cover" not the whole document, but only a part of it
        //.NET's built in "CheckSignature" does not cover this case, it will validate to true.
        //We should check the signature reference, so it "references" the id of the root document element! If not - it's a hack
        private bool ValidateSignatureReference(SignedXml signedXml)
        {
            if (signedXml.SignedInfo.References.Count != 1) //no ref at all
            {
                return false;
            }

            var reference = (Reference)signedXml.SignedInfo.References[0];
            var id = reference.Uri.Substring(1);

            var idElement = signedXml.GetIdElement(_xmlDoc, id);

            if (idElement == _xmlDoc.DocumentElement)
            {
                return true;
            }
            else //sometimes its not the "root" doc-element that is being signed, but the "assertion" element
            {
                var assertionNode = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion", _xmlNameSpaceManager) as XmlElement;
                if (assertionNode == idElement)
                {
                    return true;
                }
            }

            return false;
        }

        private bool IsExpired()
        {
            var expirationDate = DateTime.MaxValue;
            var node = _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertion}/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", _xmlNameSpaceManager);
            if (node?.Attributes["NotOnOrAfter"] != null)
            {
                DateTime.TryParse(node.Attributes["NotOnOrAfter"].Value, out expirationDate);
            }

            if (DateTime.UtcNow > expirationDate.ToUniversalTime())
            {
                // Subject.SubjectConfirmation has expired
                return true;
            }

            node = _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertion}/saml:Conditions", _xmlNameSpaceManager);
            if (node != null)
            {
                if (node?.Attributes["NotOnOrAfter"] != null)
                {
                    DateTime.TryParse(node.Attributes["NotOnOrAfter"].Value, out expirationDate);
                }

                if (DateTime.UtcNow > expirationDate.ToUniversalTime())
                {
                    // Assertion has expired
                    return true;
                }
            }

            return false;
        }

        private bool IsExpectedAudience(string expectedAudience)
        {
            var node = _xmlDoc.SelectSingleNode($"{XPaths.FirstAssertion}/saml:Conditions/saml:AudienceRestriction/saml:Audience", _xmlNameSpaceManager);
            return node == null || node.InnerText == expectedAudience;
        }

        private static class XPaths
        {
            public static string FirstAssertion = "/samlp:Response/saml:Assertion[1]";
            public static string FirstAssertionsAttributeStatement => $"{FirstAssertion}/saml:AttributeStatement";
        }
    }
}