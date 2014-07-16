from __future__ import absolute_import, division, print_function, unicode_literals
import re
from contextlib import contextmanager
import requests
import jam_saml


class JamSession(object):
    def __init__(self, server_url, issuer, private_key, client_id, client_secret, jam_access_email):
        self.server_url = server_url
        self.issuer = issuer
        self.private_key= private_key
        self.client_id = client_id
        self.client_secret = client_secret
        self.jam_access_email = jam_access_email

    def url_for(self, relative_url):
        return self.server_url + '/' + relative_url.lstrip('/')

    @property
    def access_token(self):
        if not hasattr(self, '_jam_token'):
            self._jam_token = self.get_access_token()
        return self._jam_token

    def get_access_token(self):
        assertion = self.get_assertion()
        return self.request_token(assertion)

    def get_assertion(self):
        user_id = self.jam_access_email

        unsigned_assertion = jam_saml.generate_assertion(
            issuer=self.issuer,
            jam_root_url=self.server_url,
            user_id=user_id,
            client_id=self.client_id
        )
        return jam_saml.sign_assertion(unsigned_assertion, self.private_key)

    def request_token(self, assertion):
        encoded_assertion = re.sub(r'\s', '', assertion.encode('base64'))
        post_params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type="urn:ietf:params:oauth:grant-type:saml2-bearer",
            assertion=encoded_assertion,
        )

        token_url = self.url_for("/api/v1/auth/token")
        response = requests.post(token_url, data=post_params)
        response.raise_for_status()
        return response.json()['access_token']

    @contextmanager
    def headers(self, request_params):
        headers = request_params.get('headers', {})

        yield headers

        request_params['headers'] = headers

    def auth_header(self, request_params):
        if "headers" not in request_params:
            request_params["headers"] = {}

        with self.headers(request_params) as headers:
            headers["authorization"] = 'OAuth {}'.format(self.access_token)
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
