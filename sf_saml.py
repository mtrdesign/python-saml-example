from __future__ import absolute_import, division, print_function, unicode_literals
import xmlsec
from lxml import etree
import pytz
from datetime import datetime, timedelta
import cStringIO


def generate_assertion(sf_root_url, user_id, client_id):
    issue_instant = datetime.utcnow().replace(tzinfo=pytz.utc)
    auth_instant = issue_instant
    not_valid_before = issue_instant - timedelta(minutes=10)
    not_valid_after = issue_instant + timedelta(minutes=10)

    audience = 'www.successfactors.com'

    context = dict(
        issue_instant=issue_instant.isoformat(),
        auth_instant=auth_instant.isoformat(),
        not_valid_before=not_valid_before.isoformat(),
        not_valid_after=not_valid_after.isoformat(),
        sf_root_url=sf_root_url,
        audience=audience,
        user_id=user_id,
        client_id=client_id,
        session_id='mock_session_index',
    )

    return SAML_ASSERTION_TEMPLATE.format(**context)


def sign_assertion(xml_string, private_key):
    key = xmlsec.Key.from_file(private_key, xmlsec.KeyFormat.PEM)

    root = etree.fromstring(xml_string)
    signature_node = xmlsec.tree.find_node(root, xmlsec.Node.SIGNATURE)

    sign_context = xmlsec.SignatureContext()
    sign_context.key = key
    sign_context.sign(signature_node)

    return etree.tostring(root)


SAML_ASSERTION_TEMPLATE = """
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
"""
