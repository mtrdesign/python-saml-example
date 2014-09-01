# SAP SuccessFactors SAML Authentication

The SuccessFactors API gives us access to any data entity in the system with an easy to use interface. And I really mean easy -- the coolest thing about it is that it is based on the OData standard. OData is both simple to use in ad-hoc requests and there are a lot of client libraries out there that can make building queries easier. I usually prefer the former approach.

The OData specification does not specify an authentication and authorization mechanism, and the SuccessFactors team has decided to embrace another popular standard: OAuth 2.0 using the SAML bearer assertion flow. The SFSF SAML authentication story is not too different than the [Jam one](jam_saml.md), but it has its own quirks. In a way it could be a lot easier to use SAML assertions with SuccessFactors, but that comes with a price - there is an associated security risk that I will help you avoid by doing some extra work.

The plan for this guide:

* Configuring SuccessFactors for OAuth authentication.
* Generating SAML assertions:
** Using the SFSF API.
** Using our own XML-signing code.
* Obtaining an access token.
* Authenticating OData requests.

## OAuth Access Configuration

Unlike Jam, when working with SuccessFactors authentication, all you need to do is configure an OAuth client application. SFSF is smart enough to use it as an identity provider if you configure an X.509 certificate for your application.

Registering the application goes as following:

1. Generate a RSA key pair and export your public key as a X.509 certificate. Use the `generate_keys.sh` tool and consult [the Jam SAML article](jam_saml.md) if you get stuck.
2. Go to the SFSF AdminTools page and add a new OAuth client. Paste your X.509 certificate body in the textbox:

![OAuth settings](https://raw.githubusercontent.com/mtrdesign/python-saml-example/master/doc/img/sf-oauth-client-settings.png)

Note: OpenSSL-generated certificates contain `-----BEGIN CERTIFICATE-----`/`-----END CERTIFICATE-----` text guards in their first and last lines respectively. The SuccessFactors admin seems to choke on those, so you need to remove the first and last lines. Just select the certificate body between those lines and paste it in the textbox above.

## Generating the SAML assertion

There are two ways you can generate a SuccessFactors SAML assertion:

* By using the SFSF assertion API.
* By generating it and signing it yourself.

I'd like to take the moment and give you a warning against using the assertion API in production. First, there is the performance side of the story -- there is an extra server roundtrip involved every time you authenticate against the server which can get slow.

Even more important here are the security implications. In order to generate and sign a SAML assertion, the server needs access to your *_private_* key. Read that again -- you will be giving out your private key to someone else. That doesn't sit too well with me. I'd recommend that you try the API a couple of times to get a hold on the generated assertion document and then start generating that yourself.

### Using the SuccessFactors Assertion API

With the above warning in place, let's get started talking to the assertion API. We need to issue a HTTP POST request to the `/oauth/idp` resource and pass the OAuth client id, our authenticated user ID, the access token generation URL (used as the next authentication step), and our specially formatted private key.

```python
def get_assertion_from_sf(self):
    """
    Send our private key to the SFSF IdP API and let it generate an assertion for us.
    Not ideal and incurs an additional API roundtrip. Use only for testing/debugging purposes.
    """
    user_id = self.sf_user_id
    with open(self.private_key) as key_file:
        # remove ---BEGIN/---END lines (first and last)
        # strip whitespace and squash everything on a single line
        flattened_key = ''.join([l.strip() for l in key_file.readlines()[1:-1]])

    assertion_request = dict(
        client_id=self.oauth_client_id,
        user_id=user_id,
        token_url=self.odata_url,
        private_key=flattened_key,
    )
    response = requests.post(self.idp_url, data=assertion_request)
    response.raise_for_status()
    return response.content
```

Note the key "flattening" logic above. We need to get rid of our first and last lines (containing the -----BEGIN RSA PRIVATE KEY-----/-----END RSA PRIVATE KEY----- markers), strip whitespace and squash everything in a single line.

The assertion we get back is a single-line base64-encoded XML document that we can just pass to the access code API (see below).

### Generating an Assertion Ourselves

A quick base64-decode on the SAML document we get from the API above can show us how we can generate such a document ourselves. Here are the data items we need:

* The recipient URL -- set to the SFSF OData URL.
* The SAML audience string -- hardcoded to `www.successfactors.com`.
* The authenticated user ID.
* The OAuth application client ID.
* A session id that doesn't matter too much. We hardcode it to `mocksession`.
* Some timestamps: authentication instant and expiration times.

And now the XML template:

```xml
<saml2:Assertion
IssueInstant="{issue_instant}" Version="2.0"
xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
xmlns:xs="http://www.w3.org/2001/XMLSchema"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <saml2:Issuer>{client_id}</saml2:Issuer>
  <saml2:Subject>
    <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{user_id}</saml2:NameID>
    <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">

      <saml2:SubjectConfirmationData NotOnOrAfter="{not_valid_after}"
      Recipient="{sf_root_url}/odata/v2" />
    </saml2:SubjectConfirmation>
  </saml2:Subject>
  <saml2:Conditions NotBefore="{not_valid_before}"
  NotOnOrAfter="{not_valid_after}">
    <saml2:AudienceRestriction>
      <saml2:Audience>{audience}</saml2:Audience>
    </saml2:AudienceRestriction>
  </saml2:Conditions>
  <saml2:AuthnStatement AuthnInstant="{issue_instant}"
  SessionIndex="{session_id}">
    <saml2:AuthnContext>
      <saml2:AuthnContextClassRef>
      urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
    </saml2:AuthnContext>
  </saml2:AuthnStatement>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
        <DigestValue></DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue/>
  </Signature>
</saml2:Assertion>
```

We can now use an approach similar to the one used when generating and signing Jam assertions:

```python
def get_local_assertion(self):
    """
    Generate and sign the SAML assertion ourselves.
    """
    user_id = self.sf_user_id

    unsigned_assertion = sf_saml.generate_assertion(
        sf_root_url=self.server_url,
        user_id=user_id,
        client_id=self.oauth_client_id
    )
    signed = sf_saml.sign_assertion(unsigned_assertion, self.private_key)
    return signed.encode('base64').replace('\n', '')
```

The `sf_saml` module takes care of generating and signing assertions and is very similar to the code we used to handle [Jam assertions](jam_saml.md).

Note that at the end of the function above we still need to base64-encode our signed XML and squash it into a single line.

## Obtaining an Access Token

Armed with our assertion, we can now ask for an access token using a HTTP POST request against `/oauth/token`. The only thing worth mentioning here is that we need to pass a `grant_type` parameter of `urn:ietf:params:oauth:grant-type:saml2-bearer` and include our OAuth client ID, our company ID and the assertion as well.

```python
def get_access_token(self, assertion=None):
    if not assertion:
        assertion = self.get_local_assertion()

    token_request = dict(
        client_id=self.oauth_client_id,
        company_id=self.company_id,
        grant_type='urn:ietf:params:oauth:grant-type:saml2-bearer',
        assertion=assertion
    )
    response = requests.post(self.access_token_url, data=token_request)
    token_data = response.json()
    return (token_data['access_token'], token_data['expires_in'])
```

## Token Authentication for OData Requests

Having gotten an access token, we can now issue OData requests. All we need is to pass the token via the `Authorization` HTTP header:

headers["authorization"] = 'Bearer {}'.format(self.access_token)

A minor detail above that needs mentioning: the token needs to be prefixed with the `Bearer ` string to indicate its type.

We can now pack everything together in a single `SFSession` class that wraps the "requests" `get`/`post` API and calls our SFSF server. Here is an example that fetches our user details:


```python
SF_URL = os.getenv('SF_URL')
SF_SAML_PRIVATE_KEY = 'sf-private.pem'
SF_USER = sys.argv[1]
SF_COMPANY_ID = os.getenv('SF_COMPANY_ID')
SF_OAUTH_CLIENT_ID = os.getenv('SF_OAUTH_CLIENT_ID')
SF_OAUTH_CLIENT_SECRET = os.getenv('SF_OAUTH_CLIENT_SECRET')

session = SFSession(server_url=SF_URL,
                    private_key=SF_SAML_PRIVATE_KEY,
                    company_id=SF_COMPANY_ID,
                    oauth_client_id=SF_OAUTH_CLIENT_ID,
                    sf_user_id=SF_USER)
response = session.get("/odata/v2/User?$filter=userId eq '{}'".format(SF_USER))
```

The OData query is so simple, we don't even need to take care of much URL escapes most of the time. I really like that protocol.

Running the code above we get a JSON document:
```python
{u'd': {u'results': [{u'__metadata': {u'type': u'SFOData.User',
                      ...
                      u'addressLine1': u'1500 Fashion Island Blvd',
                      u'city': u'San Mateo',
                      u'country': u'United States',
                      u'custom10': u'admin',
                      u'dateOfCurrentPosition': u'/Date(983404800000)/',
                      u'dateOfPosition': u'/Date(1388534400000)/',
                      u'defaultLocale': u'en_US',
                      u'department': u'Industries (IND)',
                      u'division': u'Industries (IND)',
                      u'email': u'admin@ACEcompany.com',
                      u'firstName': u'Emily',
                      u'lastName': u'Clark',
                      ...
                      u'zipCode': u'94404'}]}}
```

## Source Code

The full source code is available on [GitHub](https://github.com/mtrdesign/python-saml-example).

Things of interest in the project dir:

* requirements.txt to set up your virtualenv.
* generate_keys.sh to, well, generate RSA keys.
* sf_saml.py generates and signs SAML assertions.
* sap_sf.py authenticates and makes requests to the Jam API.
* get_sf_user.py makes a sample API call that retrieves member details.
