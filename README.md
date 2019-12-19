![](https://github.com/mrtristan/CoreSaml2Utils/workflows/.NET%20Core/badge.svg)
[![NuGet version (CoreSaml2Utils)](https://img.shields.io/nuget/v/CoreSaml2Utils.svg)](https://www.nuget.org/packages/CoreSaml2Utils/)

# CoreSaml2Utils
> forked from https://github.com/jitbit/AspNetSaml

Started from the Jitbit repo but had a need for more advanced concepts like decryption and signing, so wound up refactoring a bunch as I went. Became too much of a deviation to PR at this point. Published to nuget, linked above.

## usage examples
> condensed for brevity

### get a redirect url
```c#
var cert = CertificateUtilities.LoadCertificateFile(@"your_no_password_cert.pfx");

var request = new AuthnRequestFactory(
						"https://your-issuer-url.com/saml2",
						"https://your-issuer-assertion-url.com/saml2/assert",
						"https://some-idp-forward-url.com/xxxx",
						cert: cert
					);

var redirectUrl = request.GetRedirectUrl(config.IdpForwardPath, relayState, sign: cert != null);
```

### handle an assertion
```c#
var assertionParser = new AssertionParser();
assertionParser.LoadXmlFromBase64(Request.Form["SAMLResponse"]);

var issuer = assertionParser.GetResponseIssuer();
assertionParser.LoadIdpPublicKey(config.CertificateBody);

var cert = CertificateUtilities.LoadCertificateFile(@"your_no_password_cert.pfx");
assertionParser.DecryptIfNeeded(cert);

if (assertionParser.IsValid(expectedAudience: "https://your-issuer-url.com/saml2",))
{
	var authPayload = new
	{
		RelayState = Request.Form["RelayState"],
		VendorUserId = assertionParser.GetNameID(),
		Email = assertionParser.GetEmail(),
		FirstName = assertionParser.GetFirstName(),
		LastName = assertionParser.GetLastName(),
		Groups = assertionParser.GetGroupSIDs()
	};

	// do something with the user
}
```