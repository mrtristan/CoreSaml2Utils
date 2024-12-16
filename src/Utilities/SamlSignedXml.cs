using System.Security.Cryptography.Xml;
using System.Xml;

namespace CoreSaml2Utils.Utilities;

/// <summary>
/// https://github.com/optiklab/SAML-integration-utilities/blob/main/src/SamlIntegration.Utilities/Helpers/SamlSignedXml.cs
/// </summary>
internal class SamlSignedXml : SignedXml
{
    private readonly string _referenceAttributeId;

    public SamlSignedXml(XmlDocument document, string referenceAttributeId) : base(document)
    {
        _referenceAttributeId = referenceAttributeId;
    }

    public SamlSignedXml(XmlElement element, string referenceAttributeId) : base(element)
    {
        _referenceAttributeId = referenceAttributeId;
    }

    public override XmlElement GetIdElement(XmlDocument document, string idValue)
        => (XmlElement)document.SelectSingleNode($"//*[@{_referenceAttributeId}='{idValue}']");
}