using CoreSaml2Utils.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace CoreSaml2Utils
{
    public class AssertionParser
    {
        private readonly XmlDocument _xmlDoc;
        private readonly XmlNamespaceManager _xmlNameSpaceManager;

        public AssertionParser(
            XmlDocument xmlDoc,
            XmlNamespaceManager xmlNamespaceManager
        )
        {
            _xmlDoc = xmlDoc;
            _xmlNameSpaceManager = xmlNamespaceManager;
        }

        public bool IsValid(string expectedAudience, X509Certificate2 idpCert)
        {
            if (idpCert == null)
            {
                throw new ArgumentNullException(nameof(idpCert));
            }

            var nodeList = SelectNodes("//ds:Signature");

            if (nodeList.Count == 0)
            {
                return false;
            }

            var signedXml = new SignedXml(_xmlDoc);
            signedXml.LoadXml((XmlElement)nodeList[0]);

            return ValidateSignatureReference(signedXml)
                   && signedXml.CheckSignature(idpCert, true)
                   && !IsExpired()
                   && IsSuccessfulResponse()
                   && ResponseIssuerMatchesAssertionIssuer()
                   && IsExpectedAudience(expectedAudience);
        }

        public string GetResponseIssuer()
        {
            var node = SelectSingleNode("/samlp:Response/saml:Issuer");
            return node?.InnerText;
        }

        public string GetNameID()
        {
            var node = SelectSingleNode($"{XPaths.FirstAssertion}/saml:Subject/saml:NameID");
            return node?.InnerText;
        }

        public string[] GetGroupSIDs()
            => SelectNodeValues($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid']/saml:AttributeValue");

        public string[] GetGroups()
            => SelectNodeValues($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.microsoft.com/ws/2008/06/identity/claims/groups']/saml:AttributeValue");

        public string GetEmail(string[] additionalAttributeNames = null)
            => SelectFirstMatchingAttributeValue(
                                                 new List<string>
                                                     {
                                                         "mail",
                                                         "User.email",
                                                         "EmailAddress",
                                                         "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                                                     }
                                                     .Concat(additionalAttributeNames ?? [])
                                                );

        public string GetFirstName(string[] additionalAttributeNames = null)
            => SelectFirstMatchingAttributeValue(
                                                 new List<string>
                                                     {
                                                         "givenName",
                                                         "first_name",
                                                         "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
                                                         "User.FirstName",
                                                         "FirstName"
                                                     }
                                                     .Concat(additionalAttributeNames ?? [])
                                                );

        public string GetLastName(string[] additionalAttributeNames = null)
            => SelectFirstMatchingAttributeValue(
                                                 new List<string>
                                                     {
                                                         "sn",
                                                         "last_name",
                                                         "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
                                                         "User.LastName",
                                                         "LastName",
                                                     }
                                                     .Concat(additionalAttributeNames ?? [])
                                                );

        public string[] GetDepartments(string[] additionalAttributeNames = null)
            => SelectNodeValues($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department']/saml:AttributeValue");

        public string GetPhone(string[] additionalAttributeNames = null)
            => SelectFirstMatchingAttributeValue(
                                                 new List<string>
                                                     {
                                                         "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone",
                                                         "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/telephonenumber"
                                                     }
                                                     .Concat(additionalAttributeNames ?? [])
                                                );

        public string GetCompany(string[] additionalAttributeNames = null)
            => SelectFirstMatchingAttributeValue(
                                                 new List<string>
                                                     {
                                                         "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/companyname",
                                                         "User.CompanyName"
                                                     }
                                                     .Concat(additionalAttributeNames ?? [])
                                                );

        public string SelectFirstMatchingAttributeValue(IEnumerable<string> attributeNames)
        {
            foreach (var attributeName in attributeNames.Distinct())
            {
                var node = SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='{attributeName}']/saml:AttributeValue");
                if (node != null)
                {
                    return node.InnerText;
                }
            }

            return null;
        }

        public string Xml => _xmlDoc.OuterXml;

        public XmlNode SelectSingleNode(string xPath)
            => _xmlDoc.SelectSingleNode(xPath, _xmlNameSpaceManager);

        public XmlNodeList SelectNodes(string xPath)
            => _xmlDoc.SelectNodes(xPath, _xmlNameSpaceManager);

        public string[] SelectNodeValues(string xPath)
            => SelectNodes(xPath)
               ?.Cast<XmlNode>()
               .Select(x => x?.InnerText)
               .Where(x => x != null)
               .ToArray()
               ?? [];

        public Dictionary<string, string[]> GetAssertionAttributes()
            => _xmlDoc.SelectNodes($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute", _xmlNameSpaceManager)
                      ?.Cast<XmlNode>()
                      .Select(x => new
                                   {
                                       Name = x.Attributes["Name"].Value,
                                       Values = x.SelectNodes("saml:AttributeValue", _xmlNameSpaceManager)
                                                 ?.Cast<XmlNode>()
                                                 .Select(y => y.InnerText)
                                                 .ToArray()
                                   })
                      .GroupBy(x => x.Name)
                      .ToDictionary(
                                    x => x.Key,
                                    x => x.SelectMany(y => y.Values)
                                          .Distinct()
                                          .ToArray()
                                   );

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
                var assertionNode = SelectSingleNode("/samlp:Response/saml:Assertion") as XmlElement;
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
            var node = SelectSingleNode($"{XPaths.FirstAssertion}/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData");
            if (node?.Attributes["NotOnOrAfter"] != null)
            {
                DateTime.TryParse(node.Attributes["NotOnOrAfter"].Value, out expirationDate);
            }

            if (DateTime.UtcNow > expirationDate.ToUniversalTime())
            {
                // Subject.SubjectConfirmation has expired
                return true;
            }

            node = SelectSingleNode($"{XPaths.FirstAssertion}/saml:Conditions");
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

        private bool IsSuccessfulResponse()
        {
            var node = SelectSingleNode("/samlp:Response/samlp:Status/samlp:StatusCode");
            return node?.Attributes["Value"].Value == "urn:oasis:names:tc:SAML:2.0:status:Success";
        }

        private bool IsExpectedAudience(string expectedAudience)
        {
            var node = SelectSingleNode($"{XPaths.FirstAssertion}/saml:Conditions/saml:AudienceRestriction/saml:Audience");
            return node == null || node.InnerText == expectedAudience;
        }

        private bool ResponseIssuerMatchesAssertionIssuer()
        {
            var responseIssuer = SelectSingleNode($"{XPaths.FirstAssertion}/Issuer")?.Value;
            var assertionIssuer = SelectSingleNode($"/samlp:Response/Issuer")?.Value;
            return responseIssuer == assertionIssuer;
        }
    }
}