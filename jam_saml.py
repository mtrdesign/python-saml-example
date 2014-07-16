
from __future__ import absolute_import, division, print_function, unicode_literals
import xmlsec
from lxml import etree
import pytz
from datetime import datetime, timedelta
import cStringIO


def generate_assertion(jam_root_url, issuer, user_id, client_id):
    issue_instant = datetime.utcnow().replace(tzinfo=pytz.utc)
    auth_instant = issue_instant
    not_valid_before = issue_instant - timedelta(minutes=10)
    not_valid_after = issue_instant + timedelta(minutes=10)

    audience = 'cubetree.com'

    context = dict(
        issuer=issuer,
        issue_instant=issue_instant.isoformat(),
        auth_instant=auth_instant.isoformat(),
        not_valid_before=not_valid_before.isoformat(),
        not_valid_after=not_valid_after.isoformat(),
        jam_root_url=jam_root_url,
        audience=audience,
        user_id=user_id,
        client_id=client_id,
    )

    return SAML_ASSERTION_TEMPLATE.format(**context)


def sign_assertion(xml_string, private_key=None):
    if not private_key:
        private_key = settings.JAM_SAML_PRIVATE_KEY

    root = etree.fromstring(xml_string)

    signature_node = xmlsec.tree.find_node(root, xmlsec.Node.SIGNATURE)
    key = xmlsec.Key.from_file(private_key, xmlsec.KeyFormat.PEM)

    sign_context = xmlsec.SignatureContext()
    sign_context.key = key
    sign_context.sign(signature_node)

    return etree.tostring(root)



SAML_ASSERTION_TEMPLATE = """
<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
xmlns:ns2="http://www.w3.org/2000/09/xmldsig#"
xmlns:ns3="http://www.w3.org/2001/04/xmlenc#" ID="bo.ilic.test.idp"
IssueInstant="{issue_instant}" Version="2.0">
  <Issuer>{issuer}</Issuer>
  <Subject>
    <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{user_id}</NameID>
    <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">

      <SubjectConfirmationData NotOnOrAfter="{not_valid_after}"
        Recipient="{jam_root_url}/api/v1/auth/token" />
    </SubjectConfirmation>
  </Subject>
  <Conditions NotBefore="{not_valid_before}"
  NotOnOrAfter="2014-04-15T14:36:22.235Z">
    <AudienceRestriction>
      <Audience>{audience}</Audience>
    </AudienceRestriction>
  </Conditions>
  <AuthnStatement AuthnInstant="{auth_instant}"
  SessionIndex="mock_session_index">
    <AuthnContext>
      <AuthnContextClassRef>
      urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef>
    </AuthnContext>
  </AuthnStatement>
  <AttributeStatement>
    <Attribute Name="client_id">
      <AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:type="xs:string">{client_id}</AttributeValue>
    </Attribute>
  </AttributeStatement>
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
</Assertion>
"""
