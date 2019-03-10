namespace CoreSaml2Utils.Utilities
{
    public static class XPaths
    {
        public static string FirstAssertion = "/samlp:Response/saml:Assertion[1]";
        public static string FirstAssertionsAttributeStatement => $"{FirstAssertion}/saml:AttributeStatement";
    }
}