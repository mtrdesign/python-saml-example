from __future__ import absolute_import, division, print_function, unicode_literals
import requests
from contextlib import contextmanager
import sf_saml

import logging
logger = logging.getLogger(__name__)


class SFSession(object):
    def __init__(self, server_url, company_id, oauth_client_id, private_key, sf_user_id):
        self.server_url = server_url
        self.idp_url = self.url_for('/oauth/idp')
        self.access_token_url = self.url_for('/oauth/token')
        self.odata_url = self.url_for('/odata/v2')

        self.company_id = company_id
        self.oauth_client_id = oauth_client_id
        self.private_key = private_key
        self.sf_user_id = sf_user_id

    def url_for(self, relative_url):
        return self.server_url + '/' + relative_url.lstrip('/')

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

    @property
    def access_token(self):
        if hasattr(self, '_access_token'):
            return self._access_token

        self._access_token, _ = self.get_access_token()
        return self._access_token

    @contextmanager
    def headers(self, request_params):
        headers = request_params.get('headers', {})
        yield headers
        request_params['headers'] = headers

    def auth_header(self, request_params):
        if "headers" not in request_params:
            request_params["headers"] = {}

        with self.headers(request_params) as headers:
            headers["authorization"] = 'Bearer {}'.format(self.access_token)
        return request_params

    def json_format_header(self, request_params):
        with self.headers(request_params) as headers:
            if 'accept' not in headers:
                accept_header = None
            else:
                accept_header = headers['accept']

            if not accept_header:
                accept_header = 'application/json'
            elif 'application/json' not in accept_header:
                accept_header += ',' + 'application/json'

            headers['accept'] = accept_header

    def get(self, relative_url, **kwargs):
        self.auth_header(kwargs)
        self.json_format_header(kwargs)
        response = requests.get(self.url_for(relative_url), **kwargs)
        response.raise_for_status()
        return response

    def post(self, relative_url, data, **kwargs):
        self.auth_header(kwargs)
        self.json_format_header(kwargs)
        response = requests.post(self.url_for(relative_url), data, **kwargs)
        response.raise_for_status()
        return response

    def find_by_userid(self, userid):
        url = "/odata/v2/User?$filter=userId eq '{}'".format(userid)
        response = self.get(url).json()
        results = response['d']['results']
        return results[0] if results else None

    def test_access(self):
        url = '/odata/v2/User?$top=1'
        response = self.get(url).json()
        return bool(response['d'])
