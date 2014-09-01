from __future__ import absolute_import, division, print_function, unicode_literals
import sys
import os
from pprint import pprint
from sap_sf import SFSession

"""
Sample console invocation:

SF_URL=https://<sf-server>.successfactors.com \
    SF_COMPANY_ID=xxxxxxxx \
    SF_OAUTH_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
    python get_sf_user.py admin
"""


# Uncomment to see HTTP request traces on the console
import httplib
httplib.HTTPConnection.debuglevel = 1


SF_URL = os.getenv('SF_URL')
SF_SAML_PRIVATE_KEY = 'jam-private.pem'
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
pprint(response.json())
