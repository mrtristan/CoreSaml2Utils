using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace CoreSaml2Utils
{
    public static class AssertionParserFactory
    {
        public static AssertionParser LoadXmlFromBase64(string response, X509Certificate2 spCert = null)
        {
            var enc = new UTF8Encoding();
            var decoded = enc.GetString(Convert.FromBase64String(response));
            return LoadXml(decoded, spCert);
        }

        // ReSharper disable once MemberCanBePrivate.Global
        public static AssertionParser LoadXml(string xml, X509Certificate2 spCert = null)
        {
            var xmlDoc = new XmlDocument
                         {
                             PreserveWhitespace = true,
                             XmlResolver = null
                         };
            xmlDoc.LoadXml(xml);

            //returns namespace manager, we need one b/c MS says so... Otherwise XPath doesnt work in an XML doc with namespaces
            //see https://stackoverflow.com/questions/7178111/why-is-xmlnamespacemanager-necessary
            var namespaceManager = new XmlNamespaceManager(xmlDoc.NameTable);
            namespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            namespaceManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            namespaceManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            namespaceManager.AddNamespace("e", EncryptedXml.XmlEncNamespaceUrl);
            namespaceManager.AddNamespace("xenc", EncryptedXml.XmlEncNamespaceUrl);

            if (spCert != null)
            {
                var responseNode = xmlDoc.SelectSingleNode("/samlp:Response", namespaceManager);
                var encryptedAssertionNode = xmlDoc.SelectSingleNode("/samlp:Response/saml:EncryptedAssertion", namespaceManager);

                if (encryptedAssertionNode != null)
                {
                    var encryptedDataNode = xmlDoc.SelectSingleNode(
                                                                    "/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData",
                                                                    namespaceManager
                                                                   );
                    var encryptionMethodAlgorithm = xmlDoc.SelectSingleNode(
                                                                            "/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/xenc:EncryptionMethod",
                                                                            namespaceManager
                                                                           )
                                                          ?.Attributes?["Algorithm"]
                                                          ?.Value;
                    var encryptionMethodKeyAlgorithm = xmlDoc.SelectSingleNode(
                                                                               "/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/e:EncryptedKey/e:EncryptionMethod",
                                                                               namespaceManager
                                                                              )
                                                             ?.Attributes?["Algorithm"]
                                                             ?.Value;
                    var cypherText = xmlDoc.SelectSingleNode(
                                                             "/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/e:EncryptedKey/e:CipherData/e:CipherValue",
                                                             namespaceManager
                                                            )
                                           ?.InnerText;

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

            return new AssertionParser(xmlDoc, namespaceManager);
        }
    }
}