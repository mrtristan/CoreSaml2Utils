using CoreSaml2Utils.Utilities;
using System;
using System.Linq;
using System.Security.Cryptography;
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

        public void LoadIdpPublicKeyFromFile(string file)
        {
            _idpPublicKey = CertificateUtilities.LoadCertificateFile(file);
        }

        public void LoadIdpPublicKey(byte[] certificateBytes)
        {
            _idpPublicKey = CertificateUtilities.LoadCertificate(certificateBytes);
        }

        public void LoadIdpPublicKey(string certificateStr)
        {
            _idpPublicKey = CertificateUtilities.LoadCertificate(certificateStr);
        }

        public void LoadXmlFromBase64(string response)
        {
            var enc = new UTF8Encoding();
            var decoded = enc.GetString(Convert.FromBase64String(response));
            LoadXml(decoded);
        }

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
            namespaceManager.AddNamespace("e", EncryptedXml.XmlEncNamespaceUrl);
            namespaceManager.AddNamespace("xenc", EncryptedXml.XmlEncNamespaceUrl);

            _xmlNameSpaceManager = namespaceManager;
        }

        public void DecryptIfNeeded(X509Certificate2 spCert)
        {
            if (spCert == null)
            {
                throw new ArgumentNullException(nameof(spCert));
            }

            var responseNode = SelectSingleNode("/samlp:Response");
            var encryptedAssertionNode = SelectSingleNode("/samlp:Response/saml:EncryptedAssertion");

            if (encryptedAssertionNode != null)
            {
                var encryptedDataNode = SelectSingleNode("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData");
                var encryptionMethodAlgorithm = SelectSingleNode("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/xenc:EncryptionMethod")?.Attributes["Algorithm"]?.Value;
                var encryptionMethodKeyAlgorithm = SelectSingleNode("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/e:EncryptedKey/e:EncryptionMethod")?.Attributes["Algorithm"]?.Value;
                var cypherText = SelectSingleNode("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/e:EncryptedKey/e:CipherData/e:CipherValue")?.InnerText;

                var key = Rijndael.Create(encryptionMethodAlgorithm);
                key.Key = EncryptedXml.DecryptKey(
                                                Convert.FromBase64String(cypherText),
                                                (RSA)spCert.PrivateKey,
                                                useOAEP: encryptionMethodKeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl
                                            );

                var encryptedXml = new EncryptedXml();
                var encryptedData = new EncryptedData();
                encryptedData.LoadXml((XmlElement)encryptedDataNode);

                var plaintext = encryptedXml.DecryptData(encryptedData, key);
                var xmlString = Encoding.UTF8.GetString(plaintext);

                var tempDoc = new XmlDocument();
                tempDoc.LoadXml(xmlString);

                var importNode = responseNode.OwnerDocument.ImportNode(tempDoc.DocumentElement, true);
                responseNode.ReplaceChild(importNode, encryptedAssertionNode);
            }
        }

        public bool IsValid(string expectedAudience)
        {
            if (_idpPublicKey == null)
            {
                throw new ArgumentNullException("Please add the idp's public key first");
            }

            var nodeList = SelectNodes("//ds:Signature");

            if (nodeList.Count == 0)
            {
                return false;
            }

            var signedXml = new SignedXml(_xmlDoc);
            signedXml.LoadXml((XmlElement)nodeList[0]);

            return ValidateSignatureReference(signedXml)
                    && signedXml.CheckSignature(_idpPublicKey, true)
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
        {
            var node = SelectNodes($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid']/saml:AttributeValue");
            return node
                    ?.Cast<XmlNode>()
                    .Select(x => x?.InnerText)
                    .Where(x => x != null)
                    .ToArray()
                ?? Array.Empty<string>();
        }

        public string[] GetGroups()
        {
            var node = SelectNodes($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.microsoft.com/ws/2008/06/identity/claims/groups']/saml:AttributeValue");
            return node
                    ?.Cast<XmlNode>()
                    .Select(x => x?.InnerText)
                    .Where(x => x != null)
                    .ToArray()
                ?? Array.Empty<string>();
        }

        public string GetEmail()
        {
            var node = SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='User.email']/saml:AttributeValue")
                        ?? SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='EmailAddress']/saml:AttributeValue")
                        ?? SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']/saml:AttributeValue");

            return node?.InnerText;
        }

        public string GetFirstName()
        {
            var node = SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='first_name']/saml:AttributeValue")
                        ?? SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname']/saml:AttributeValue")
                        ?? SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='User.FirstName']/saml:AttributeValue")
                        ?? SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='FirstName']/saml:AttributeValue");

            return node?.InnerText;
        }

        public string GetLastName()
        {
            var node = SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='last_name']/saml:AttributeValue")
                        ?? SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname']/saml:AttributeValue")
                        ?? SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='User.LastName']/saml:AttributeValue")
                        ?? SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='LastName']/saml:AttributeValue");

            return node?.InnerText;
        }

        public string GetDepartment()
        {
            var node = SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department']/saml:AttributeValue");
            return node?.InnerText;
        }

        public string GetPhone()
        {
            var node = SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone']/saml:AttributeValue")
                        ?? SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/telephonenumber']/saml:AttributeValue");

            return node?.InnerText;
        }

        public string GetCompany()
        {
            var node = SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/companyname']/saml:AttributeValue")
                        ?? SelectSingleNode($"{XPaths.FirstAssertionsAttributeStatement}/saml:Attribute[@Name='User.CompanyName']/saml:AttributeValue");

            return node?.InnerText;
        }

        public string Xml => _xmlDoc.OuterXml;

        public XmlNode SelectSingleNode(string xPath)
        {
            return _xmlDoc.SelectSingleNode(xPath, _xmlNameSpaceManager);
        }

        public XmlNodeList SelectNodes(string xPath)
        {
            return _xmlDoc.SelectNodes(xPath, _xmlNameSpaceManager);
        }

        #endregion

        private XmlDocument _xmlDoc;
        private X509Certificate2 _idpPublicKey;
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