using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace CoreSaml2Utils.Utilities;

/// <summary>
/// https://github.com/optiklab/SAML-integration-utilities/blob/main/src/SamlIntegration.Utilities/Helpers/SigningHelper.cs#L8-L68
/// </summary>
internal class SigningHelper
{
    internal static SamlSignedXml SignXml(XmlDocument doc, X509Certificate2 certificate, string referenceId, string referenceValue)
    {
        var samlSignedXml = new SamlSignedXml(doc, referenceId);
        return SignXml(samlSignedXml, certificate, referenceValue);
    }

    internal static SamlSignedXml SignXml(XmlElement element, X509Certificate2 certificate, string referenceId, string referenceValue)
    {
        var samlSignedXml = new SamlSignedXml(element, referenceId);
        return SignXml(samlSignedXml, certificate, referenceValue);
    }

    private static SamlSignedXml SignXml(SamlSignedXml samlSignedXml, X509Certificate2 certificate, string referenceValue)
    {
        samlSignedXml.SigningKey = certificate.PrivateKey;
        samlSignedXml.SignedInfo.CanonicalizationMethod = SamlSignedXml.XmlDsigExcC14NTransformUrl;

        // Create a reference to be signed. 
        var reference = new Reference
                        {
                            Uri = "#" + referenceValue
                        };

        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());

        // Add the reference to the SignedXml object. 
        samlSignedXml.AddReference(reference);

        // Add an RSAKeyValue KeyInfo (optional; helps recipient find key to validate). 
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));

        samlSignedXml.KeyInfo = keyInfo;

        // Compute the signature. 
        samlSignedXml.ComputeSignature();

        return samlSignedXml;
    }
}