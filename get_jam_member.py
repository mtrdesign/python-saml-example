from __future__ import absolute_import, division, print_function, unicode_literals
import sys
import os
from pprint import pprint
from sap_jam import JamSession

"""
Sample console invocation:

JAM_URL=https://<jam-server>.successfactors.com \
    JAM_OAUTH_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
    JAM_OAUTH_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
    python get_jam_member.py admin@example.com
"""


# Uncomment to see HTTP request traces on the console
# import httplib
# httplib.HTTPConnection.debuglevel = 1


JAM_URL = os.getenv('JAM_URL')
JAM_SAML_PRIVATE_KEY = 'jam-private.pem'
JAM_EMAIL = sys.argv[1]
JAM_IDP_DOMAIN = 'example.com'
JAM_OAUTH_CLIENT_ID = os.getenv('JAM_OAUTH_CLIENT_ID')
JAM_OAUTH_CLIENT_SECRET = os.getenv('JAM_OAUTH_CLIENT_SECRET')

session = JamSession(server_url=JAM_URL,
                     issuer=JAM_IDP_DOMAIN,
                     private_key=JAM_SAML_PRIVATE_KEY,
                     client_id=JAM_OAUTH_CLIENT_ID,
                     client_secret=JAM_OAUTH_CLIENT_SECRET,
                     jam_access_email=JAM_EMAIL)
response = session.get('/api/v1/members')
pprint(response.json())
