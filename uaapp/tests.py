from datetime import datetime, timedelta
from contextlib import contextmanager
import json
import os
from posixpath import join as urljoin
import socket
import tempfile
import unittest

import flask
from flask import appcontext_pushed
from httmock import all_requests, HTTMock
from mock import Mock, patch
from requests.auth import HTTPBasicAuth

from uaapp.webapp import create_app
from uaapp.clients import OktaError, OktaClient, UAAError, UAAClient

app = create_app()


@contextmanager
def uaac_set(app, uaac=Mock()):
    """Shim in a mock object to flask.g"""
    def handler(sender, **kwargs):
        flask.g.uaac = uaac
    with appcontext_pushed.connected_to(handler, app):
        yield


class TestAppConfig(unittest.TestCase):
    def test_config_env_override(self):
        """Configuration is loaded from UAAPP_SETTINGS env var if provided"""

        try:
            fh, filename = tempfile.mkstemp()
            os.write(fh, b"FOO='bar'\n")
            os.close(fh)
            os.environ['UAAPP_SETTINGS'] = filename

            app = create_app()
            assert app.config['FOO'] == 'bar'
        finally:
            del os.environ['UAAPP_SETTINGS']
            os.remove(filename)

    def test_config_okta_provider(self):
        """OKTA provider is active is config vars are present"""

        try:
            fh, filename = tempfile.mkstemp()
            os.write(fh, b"OKTA_BASE_URL='http://bar/'\nOKTA_API_TOKEN='foo'\n")
            os.close(fh)
            os.environ['UAAPP_SETTINGS'] = filename

            app = create_app()
            assert isinstance(app.config['PROVIDERS']['bar'], OktaClient)
        finally:
            del os.environ['UAAPP_SETTINGS']
            os.remove(filename)

    def test_default_api_is_v1(self):
        """/api/ redirects to /api/v1"""
        with uaac_set(app):
            with app.test_client() as c:
                rv = c.get('/api/')

                assert rv.status_code == 302
                assert rv.location == 'http://localhost/api/v1/'

    @patch('uaapp.webapp.UAAClient')
    def test_uaac_is_created_from_session(self, uaac):
        """When a request is made, and a valid session exists g.uaac is created"""
        with app.test_request_context('/'):
            with app.test_client() as c:
                with c.session_transaction() as sess:
                    sess['UAA_TOKEN'] = 'foo'
                    sess['UAA_TOKEN_EXPIRES'] = datetime.utcnow() + timedelta(seconds=30)

                c.get('/')

                uaac.assert_called_with(app.config['UAA_BASE_URL'], 'foo', verify_tls=app.config['VERIFY_TLS'])

                assert isinstance(flask.g.uaac, Mock)

    @patch('uaapp.webapp.UAAClient')
    def test_redirect_to_uaac(self, uaac):
        """When a request is made, and no session exists, redirect to UAAC Oauth"""
        with app.test_client() as c:
            rv = c.get('/')

            assert rv.status_code == 302
            target = app.config['UAA_BASE_URL'] + '/oauth/authorize?client_id=' + app.config['UAA_CLIENT_ID']
            assert rv.location == target

    @patch('uaapp.webapp.UAAClient')
    def test_oauth_creates_session(self, uaac):
        """/oauth/login validaes codes with UAA"""

        uaac().oauth_token.return_value = {'access_token': 'foo', 'expires_in': 30, 'scope': 'bar baz'}

        with app.test_request_context('/oauth/login'):
            with app.test_client() as c:
                c.get('/oauth/login?code=123')

                assert uaac.oauth_token.called_with('123', app.config['UAA_CLIENT_ID'], app.config['UAA_CLIENT_SECRET'])

                assert flask.session['UAA_TOKEN'] == 'foo'
                assert flask.session['UAA_TOKEN_SCOPES'] == ['bar', 'baz']
                assert (flask.session['UAA_TOKEN_EXPIRES'] - datetime.utcnow()).seconds < 30


class TestAPIv1(unittest.TestCase):
    """Test the v1 API"""
    def mock_uaaerror(self, msg='oh no'):
        r = Mock()
        r.text = json.dumps({'error_description': 'oh no'})
        return UAAError(r)

    def test_unauthorized_bad(self):
        """403 is returned if g.uaac is not set"""

        with app.test_client() as c:
            rv = c.get('/api/v1/idps')

            assert rv.status_code == 403
            assert 'oauth token' in json.loads(rv.data.decode('utf-8'))['error_message']

    def test_unauthorized_good(self):
        """/ can still be read with no auth"""

        with app.test_client() as c:
            rv = c.get('/api/v1/')
            assert rv.status_code == 200

    def test_idps_good(self):
        """/idps returns 200 when UAAC is ok"""
        m = Mock()
        m.idps.return_value = 'foo'

        with uaac_set(app, m):
            with app.test_client() as c:
                rv = c.get('/api/v1/idps')

                m.idps.assert_called_with(active_only=True)

                assert rv.status_code == 200

                assert json.loads(rv.data.decode('utf-8'))['resources'] == 'foo'

    def test_idps_bad(self):
        """/idps returns 502 when UAAC is not ok"""
        m = Mock()
        m.idps.side_effect = self.mock_uaaerror()

        with uaac_set(app, m):
            with app.test_client() as c:
                rv = c.get('/api/v1/idps')

                m.idps.assert_called_with(active_only=True)
                assert rv.status_code == 502

                assert json.loads(rv.data.decode('utf-8'))['error_message'] == 'oh no'

    def test_users_good(self):
        """/users with no params returns raw uaac response"""
        m = Mock()
        m.users.return_value = {'resources': [], 'mock': True}

        with uaac_set(app, m):
            with app.test_client() as c:
                rv = c.get('/api/v1/users')

                assert rv.status_code == 200
                assert json.loads(rv.data.decode('utf-8'))['mock'] is True

    def test_users_bad(self):
        """/users returns 502 when UAAC is not ok"""
        m = Mock()
        m.users.side_effect = self.mock_uaaerror()
        with uaac_set(app, m):
            with app.test_client() as c:
                rv = c.get('/api/v1/users')

                assert rv.status_code == 502

    def test_users_good_origin(self):
        """/users with origin"""
        m = Mock()
        m.users.return_value = {'resources': [{'userName': 'foo@bar.gov'}]}

        with uaac_set(app, m):
            with app.test_client() as c:
                rv = c.get('/api/v1/users?origin=foo')

                assert rv.status_code == 200
                m.users.assert_called_with('origin eq "foo"')

    def test_users_good_domains(self):
        """/users with domain"""

        m = Mock()
        m.users.return_value = {'resources': [{'userName': 'foo@bar.gov'}, {'userName': 'bar.gov@example.com'}]}

        with uaac_set(app, m):
            with app.test_client() as c:
                # raw result has two users
                assert len(m.users()['resources']) == 2

                rv = c.get('/api/v1/users?domain=bar.gov')
                assert rv.status_code == 200

                # bar.gov@example.com should be filtered out
                assert len(json.loads(rv.data.decode('utf-8'))['resources']) == 1

                m.users.assert_called_with('userName co "bar.gov"')

    def test_users_good_origin_and_domains(self):
        """/users with origin and domain"""
        m = Mock()
        m.users.return_value = {'resources': []}

        with uaac_set(app, m):
            with app.test_client() as c:
                rv = c.get('/api/v1/users?origin=foo&domain=bar')

                assert rv.status_code == 200
                m.users.assert_called_with('origin eq "foo" and userName co "bar"')

    def test_migrate_no_user(self):
        """/migrate returns 400 when no user id is provided"""

        with uaac_set(app):
            with app.test_client() as c:
                rv = c.post('/api/v1/migrate')

                assert rv.status_code == 400
                assert json.loads(rv.data.decode('utf-8'))['error_message'].startswith('id')

    def test_migrate_no_origin(self):
        """/migrsate returns 400 with no origin is provided"""
        with uaac_set(app):
            with app.test_client() as c:
                rv = c.post('/api/v1/migrate', data={'id': 'foo'})

                assert rv.status_code == 400
                assert json.loads(rv.data.decode('utf-8'))['error_message'].startswith('origin')

    def test_migrate_bad_user(self):
        """/migrate returns 404 when no user cannot be found"""
        m = Mock()
        m.get_user.side_effect = self.mock_uaaerror()
        m.idps.return_value = [{'originKey': 'bar'}]

        with uaac_set(app, m):
            with app.test_client() as c:
                rv = c.post('/api/v1/migrate', data={'id': 'foo', 'origin': 'bar'})
                assert rv.status_code == 404
                assert 'user id' in json.loads(rv.data.decode('utf-8'))['error_message']

    def test_migrate_bad_origin(self):
        """/migrsate returns 404 when origin cannot be found"""
        m = Mock()
        m.idps.return_value = [{'originKey': 'baz'}]

        with uaac_set(app, m):
            with app.test_client() as c:
                rv = c.post('/api/v1/migrate', data={'id': 'foo', 'origin': 'bar'})
                assert rv.status_code == 404
                assert 'origin' in json.loads(rv.data.decode('utf-8'))['error_message']

    def test_migrate_uaa_error(self):
        """/migrate returns 502 when UAA is not ok"""
        m = Mock()
        m.get_user.return_value = {}
        m.put_user.side_effect = self.mock_uaaerror()
        m.idps.return_value = [{'originKey': 'bar'}]

        with uaac_set(app, m):
            with app.test_client() as c:
                rv = c.post('/api/v1/migrate', data={'id': 'foo', 'origin': 'bar'})
                assert rv.status_code == 502

    def test_migrate_good(self):
        """/migrate returns 200 after migrsting a user"""
        m = Mock()
        m.get_user.return_value = {}
        m.put_user.side_effect = lambda x: x
        m.idps.return_value = [{'originKey': 'bar'}]

        with uaac_set(app, m):
            with app.test_client() as c:
                rv = c.post('/api/v1/migrate', data={'id': 'foo', 'origin': 'bar'})
                assert rv.status_code == 200
                assert json.loads(rv.data.decode('utf-8'))['origin'] == 'bar'

    def test_provision_no_providers_configured(self):
        """/provision returns 501 when no providers are available"""
        app.config['PROVIDERS'] = {}
        with uaac_set(app):
            with app.test_client() as c:
                rv = c.post('/api/v1/provision')
                assert rv.status_code == 501

    def test_provision_no_provider(self):
        """/provision returns 400 when provider isn't provided"""
        app.config['PROVIDERS'] = {'foo': Mock()}
        with uaac_set(app):
            with app.test_client() as c:
                rv = c.post('/api/v1/provision')
                assert rv.status_code == 400
                assert 'provider' in json.loads(rv.data.decode('utf-8'))['error_message']

    def test_provision_bad_provider(self):
        """/provision returns 404 when provider isn't valid"""
        app.config['PROVIDERS'] = {'foo': Mock()}
        with uaac_set(app):
            with app.test_client() as c:
                rv = c.post('/api/v1/provision', data={'provider': 'bar'})
                assert rv.status_code == 404
                assert 'provider' in json.loads(rv.data.decode('utf-8'))['error_message']

    def test_provision_no_user(self):
        """/provision returns 400 when user isn't provided"""
        app.config['PROVIDERS'] = {'foo': Mock()}
        with uaac_set(app):
            with app.test_client() as c:
                rv = c.post('/api/v1/provision', data={'provider': 'foo'})
                assert rv.status_code == 400
                assert 'id' in json.loads(rv.data.decode('utf-8'))['error_message']

    def test_provision_bad_user(self):
        """/provision returns 404 when user isn't valid"""
        app.config['PROVIDERS'] = {'foo': Mock()}
        m = Mock()
        m.get_user.side_effect = self.mock_uaaerror()

        with uaac_set(app, m):
            with app.test_client() as c:
                rv = c.post('/api/v1/provision', data={'provider': 'foo', 'id': 'bar'})
                assert rv.status_code == 404
                assert 'user' in json.loads(rv.data.decode('utf-8'))['error_message']

    def test_provision_bad(self):
        """/provision returns 502 when provider fails"""
        f = Mock()
        f.provision_user.side_effect = Exception('oh no')
        app.config['PROVIDERS'] = {'foo': f}

        with uaac_set(app):
            with app.test_client() as c:
                rv = c.post('/api/v1/provision', data={'provider': 'foo', 'id': 'bar'})
                assert rv.status_code == 502
                assert 'oh no' in json.loads(rv.data.decode('utf-8'))['error_message']

    def test_provision_good(self):
        """/provision returns 201 and a location header when successful"""
        f = Mock()
        f.provision_user.return_value = 'http://example.org/a/user'
        app.config['PROVIDERS'] = {'foo': f}

        with uaac_set(app):
            with app.test_client() as c:
                rv = c.post('/api/v1/provision', data={'provider': 'foo', 'id': 'bar'})
                assert rv.status_code == 201
                assert rv.location == 'http://example.org/a/user'

    def test_email_no_user(self):
        """/email returns 400 when no user is provided"""
        with uaac_set(app):
            with app.test_client() as c:
                rv = c.post('/api/v1/email')
                assert rv.status_code == 400
                assert 'id' in json.loads(rv.data.decode('utf-8'))['error_message']

    def test_email_bad_user(self):
        """/email returns 404 when a bad user is provided"""
        m = Mock()
        m.get_user.side_effect = self.mock_uaaerror()

        with uaac_set(app, m):
            with app.test_client() as c:
                rv = c.post('/api/v1/email', data={'id': 'foo'})
                assert rv.status_code == 404
                assert 'user' in json.loads(rv.data.decode('utf-8'))['error_message']

    def test_email_no_subject(self):
        """/email returns 400 when no subject is provided"""
        with uaac_set(app):
            with app.test_client() as c:
                rv = c.post('/api/v1/email', data={'id': 'foo'})
                assert rv.status_code == 400
                assert 'subject' in json.loads(rv.data.decode('utf-8'))['error_message']
                assert 'required' in json.loads(rv.data.decode('utf-8'))['error_message']

    def test_email_bad_subject(self):
        """/email returns 400 when an invalid subject is provided"""
        with uaac_set(app):
            with app.test_client() as c:
                rv = c.post('/api/v1/email', data={'id': 'foo', 'subject': '{% lol %}'})
                assert rv.status_code == 400
                assert 'unknown tag' in json.loads(rv.data.decode('utf-8'))['error_message']

    def test_email_no_body(self):
        """/email returns 400 when no body is provided"""
        with uaac_set(app):
            with app.test_client() as c:
                rv = c.post('/api/v1/email', data={'id': 'foo', 'subject': 'y hello thar'})
                assert rv.status_code == 400
                assert 'body' in json.loads(rv.data.decode('utf-8'))['error_message']
                assert 'required' in json.loads(rv.data.decode('utf-8'))['error_message']

    def test_email_bad_body(self):
        """/email returns 400 when an invalid body is provided"""
        with uaac_set(app):
            with app.test_client() as c:
                rv = c.post('/api/v1/email', data={'id': 'foo', 'subject': 'y hello thar', 'body': '{% lol %}'})
                assert rv.status_code == 400
                assert 'unknown tag' in json.loads(rv.data.decode('utf-8'))['error_message']

    def test_email_no_send(self):
        """/email returns 200 + the render email when send is not set"""
        m = Mock()
        m.get_user.return_value = {'test': 'lol', 'userName': 'foo@bar.baz'}

        app.config['SMTP_FROM_NAME'] = 'Test Name'
        app.config['SMTP_FROM_ADDR'] = 'no-reply@example.com'
        with uaac_set(app, m):
            with app.test_client() as c:
                rv = c.post('/api/v1/email', data={
                    'id': 'foo',
                    'subject': 'y hello thar',
                    'body': 'I love to {{user.test}}'
                })
                assert rv.status_code == 200
                assert rv.data.decode('utf-8').endswith('I love to lol')

                assert 'Subject: y hello thar' in rv.data.decode('utf-8')
                assert 'From: Test Name <no-reply@example.com>' in rv.data.decode('utf-8')

    @patch('uaapp.api.smtplib')
    def test_email_send_bad(self, smtp):
        """/email returns 500 when email cannot be queued"""
        smtp.SMTP.side_effect = socket.error('oh no')

        m = Mock()
        m.get_user.return_value = {'test': 'lol', 'userName': 'foo@bar.baz'}

        app.config['SMTP_HOST'] = 'localhost'
        app.config['SMTP_PORT'] = 62525
        app.config['SMTP_FROM_NAME'] = 'Test Name'
        app.config['SMTP_FROM_ADDR'] = 'no-reply@example.com'
        with uaac_set(app, m):
            with app.test_client() as c:
                rv = c.post('/api/v1/email', data={
                    'id': 'foo',
                    'subject': 'y hello thar',
                    'body': 'I love to {{user.test}}',
                    'send': '1'
                })
                assert rv.status_code == 500
                assert json.loads(rv.data.decode('utf-8'))['error_message'] == 'oh no'

    @patch('uaapp.api.smtplib')
    def test_email_send_good(self, smtp):
        """/email returns 202 when email is sent"""
        m = Mock()
        m.get_user.return_value = {'test': 'lol', 'userName': 'foo@bar.baz'}

        app.config['SMTP_HOST'] = 'localhost'
        app.config['SMTP_PORT'] = 62525
        app.config['SMTP_FROM_NAME'] = 'Test Name'
        app.config['SMTP_FROM_ADDR'] = 'no-reply@example.com'
        with uaac_set(app, m):
            with app.test_client() as c:
                rv = c.post('/api/v1/email', data={
                    'id': 'foo',
                    'subject': 'y hello thar',
                    'body': 'I love to {{user.test}}',
                    'send': '1'
                })
                assert rv.status_code == 202
                assert len(rv.data) == 0


class TestUAAClient(unittest.TestCase):
    """Test our UAA Client"""
    def test_error_message(self):
        """Error messages are populated properly in the exception"""
        r = Mock()
        r.text = json.dumps({'error_description': 'oh no'})

        u = UAAError(r)
        assert str(u) == 'oh no'

    @patch('uaapp.clients.uaa.requests')
    def test_request_bad(self, requests):
        """UAAError is reaised when it occurs"""

        r = Mock()
        r.status_code = 500
        r.text = json.dumps({'error_description': 'oh no'})
        requests.get.return_value = r

        uaac = UAAClient('http://example.com', 'foo', True)

        with self.assertRaises(UAAError):
            uaac._request('/bar', 'GET')

        requests.get.assert_called_with(
            'http://example.com/bar',
            headers={'Authorization': 'Bearer foo'},
            json=None,
            params=None,
            auth=None,
            verify=True
        )

    @patch('uaapp.clients.uaa.requests')
    def test_request_get(self, requests):
        """GET request is made"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        requests.get.return_value = r

        uaac = UAAClient('http://example.com', 'foo', True)

        resp = uaac._request('/bar', 'GET')

        requests.get.assert_called_with(
            'http://example.com/bar',
            headers={'Authorization': 'Bearer foo'},
            json=None,
            params=None,
            auth=None,
            verify=True
        )

        assert resp['test'] == 'value'

    @patch('uaapp.clients.uaa.requests')
    def test_request_get_insecure(self, requests):
        """Insecure GET request is made"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        requests.get.return_value = r

        uaac = UAAClient('http://example.com', 'foo', False)

        resp = uaac._request('/bar', 'GET')

        requests.get.assert_called_with(
            'http://example.com/bar',
            headers={'Authorization': 'Bearer foo'},
            json=None,
            params=None,
            auth=None,
            verify=False
        )

        assert resp['test'] == 'value'

    @patch('uaapp.clients.uaa.requests')
    def test_request_get_headers(self, requests):
        """Additional headers are included if we provide them"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        requests.get.return_value = r

        uaac = UAAClient('http://example.com', 'foo', False)

        resp = uaac._request('/bar', 'GET', headers={'omg': 'lol'})

        requests.get.assert_called_with(
            'http://example.com/bar',
            headers={'omg': 'lol', 'Authorization': 'Bearer foo'},
            json=None,
            params=None,
            auth=None,
            verify=False
        )

        assert resp['test'] == 'value'

    @patch('uaapp.clients.uaa.requests')
    def test_request_get_params(self, requests):
        """Query string is sent if params are provided"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        requests.get.return_value = r

        uaac = UAAClient('http://example.com', 'foo', False)

        resp = uaac._request('/bar', 'GET', params={'omg': 'lol'})

        requests.get.assert_called_with(
            'http://example.com/bar',
            headers={'Authorization': 'Bearer foo'},
            json=None,
            params={'omg': 'lol'},
            auth=None,
            verify=False
        )

        assert resp['test'] == 'value'

    @patch('uaapp.clients.uaa.requests')
    def test_request_get_auth(self, requests):
        """Auth value is passed directly to requests"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        requests.get.return_value = r

        uaac = UAAClient('http://example.com', 'foo', False)

        resp = uaac._request('/bar', 'GET', auth='this should be basic')

        requests.get.assert_called_with(
            'http://example.com/bar',
            headers={},
            json=None,
            params=None,
            auth='this should be basic',
            verify=False
        )

        assert resp['test'] == 'value'

    @patch('uaapp.clients.uaa.requests')
    def test_request_post_body(self, requests):
        """Body is included in request if provided"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        requests.post.return_value = r

        uaac = UAAClient('http://example.com', 'foo', False)

        resp = uaac._request('/bar', 'POST', body='hi')

        requests.post.assert_called_with(
            'http://example.com/bar',
            headers={'Authorization': 'Bearer foo'},
            json='hi',
            params=None,
            auth=None,
            verify=False
        )

        assert resp['test'] == 'value'

    def test_idps(self):
        """idps() makes a GET request to /identity-providers"""

        uaac = UAAClient('http://example.com', 'foo', False)
        m = Mock()
        uaac._request = m

        uaac.idps(active_only=True)
        m.assert_called_with('/identity-providers', 'GET', params={'active_only': 'true'})

        uaac.idps(active_only=False)
        m.assert_called_with('/identity-providers', 'GET', params={'active_only': 'false'})

    def test_users(self):
        """users() makes a GET request to /Users"""

        uaac = UAAClient('http://example.com', 'foo', False)
        m = Mock()
        uaac._request = m

        uaac.users()
        m.assert_called_with('/Users', 'GET', params=None)

        uaac.users('test filter')
        m.assert_called_with('/Users', 'GET', params={'filter': 'test filter'})

    def test_get_user(self):
        """get_user() makes a GET request to /Users/<id>"""

        uaac = UAAClient('http://example.com', 'foo', False)
        m = Mock()
        uaac._request = m

        uaac.get_user('foo')
        m.assert_called_with(urljoin('/Users', 'foo'), 'GET')

    def test_put_user(self):
        """put_user() makes a PUT request to /Users/<id> with appropriate headers"""

        uaac = UAAClient('http://example.com', 'foo', False)
        m = Mock()
        uaac._request = m

        user = {
            'id': 'foo',
            'meta': {
                'version': '123'
            }
        }

        uaac.put_user(user)

        m.assert_called_with(
            urljoin('/Users', 'foo'),
            'PUT',
            body=user,
            headers={'If-Match': '123'}
        )

    def test_oauth_token(self):
        """oauth_token() makes a POST to /oauth/token with the appropriate headers and query params"""

        uaac = UAAClient('http://example.com', 'foo', False)
        m = Mock()
        uaac._request = m

        uaac.oauth_token('foo', 'bar', 'baz')

        args, kwargs = m.call_args

        assert args == ('/oauth/token', 'POST')

        assert kwargs['params'] == {
            'code': 'foo',
            'grant_type': 'authorization_code',
            'response_type': 'token'
        }

        assert isinstance(kwargs['auth'], HTTPBasicAuth)
        assert kwargs['auth'].username == 'bar'
        assert kwargs['auth'].password == 'baz'


class TestOktaClient(unittest.TestCase):
    """Test our Okta Client"""
    def test_no_error_summary(self):
        """Root errorSummary is used when errorCauses is empty"""
        @all_requests
        def dupe_user(url, request):
            return {
                'status_code': 400,
                'content': json.dumps({u'errorCode': u'E0000001', u'errorSummary': u'Api validation failed: login', u'errorLink': u'E0000001', u'errorCauses': [], u'errorId': u'oae3BEsz6SQSGyWqsveSPH-Fg'})  # NOQA
            }

        with self.assertRaises(OktaError) as oe:
            with HTTMock(dupe_user):
                oc = OktaClient('https://okta', 'token')
                oc.new_user('foo@bar.com', 'Foo', 'Bar')

            # assert the error message is commucated through the exception as we expect
            assert 'validation failed' in str(oe)

    def test_new_user_bad(self):
        """When a user cannot be created an exception is raised"""

        @all_requests
        def dupe_user(url, request):
            return {
                'status_code': 400,
                'content': json.dumps({u'errorCode': u'E0000001', u'errorSummary': u'Api validation failed: login', u'errorLink': u'E0000001', u'errorCauses': [{u'errorSummary': u'login: An object with this field already exists in the current organization'}], u'errorId': u'oae3BEsz6SQSGyWqsveSPH-Fg'})  # NOQA
            }

        with self.assertRaises(OktaError) as oe:
            with HTTMock(dupe_user):
                oc = OktaClient('https://okta', 'token')
                oc.new_user('foo@bar.com', 'Foo', 'Bar')

            # assert the error message is commucated through the exception as we expect
            assert 'already exists' in str(oe)
            assert oe.response.status_code == 400
            assert oe.error['errorCode'] == 'E0000001'

    def test_new_user_good(self):
        """We can use the Okta user to create an API"""

        @all_requests
        def good_user(url, request):
            return {
                'status_code': 200,
                'content': json.dumps({u'status': u'PROVISIONED', u'profile': {u'mobilePhone': None, u'firstName': u'Foo', u'lastName': u'Bar', u'secondEmail': None, u'login': u'foo@example.com', u'email': u'foo@example.com'}, u'passwordChanged': None, u'created': u'2016-05-03T16:55:02.000Z', u'activated': u'2016-05-03T16:55:02.000Z', u'lastUpdated': u'2016-05-03T16:55:02.000Z', u'_links': {u'deactivate': {u'href': u'https://dev-258028.oktapreview.com/api/v1/users/00u6b9thlz8kpYyk90h7/lifecycle/deactivate', u'method': u'POST'}, u'suspend': {u'href': u'https://dev-258028.oktapreview.com/api/v1/users/00u6b9thlz8kpYyk90h7/lifecycle/suspend', u'method': u'POST'}, u'resetPassword': {u'href': u'https://dev-258028.oktapreview.com/api/v1/users/00u6b9thlz8kpYyk90h7/lifecycle/reset_password', u'method': u'POST'}}, u'lastLogin': None, u'credentials': {u'provider': {u'type': u'OKTA', u'name': u'OKTA'}}, u'id': u'00u6b9thlz8kpYyk90h7', u'statusChanged': u'2016-05-03T16:55:02.000Z'})  # NOQA
            }

        with HTTMock(good_user):
            oc = OktaClient('https://okta', 'token')
            user = oc.new_user('foo@example.com', 'Foo', 'Bar')

        assert user['profile']['login'] == 'foo@example.com'

    def test_okta_provision_user_new_no_name(self):
        """Provisioning a user with no name uses the email address"""
        oc = OktaClient('https://okta', 'token')
        m = Mock()
        m.return_value = {'id': 'bork'}
        oc.new_user = m

        user = {
            'name': {
                'givenName': '',
                'familyName': ''
            },
            'userName': 'foo@bar.baz'
        }

        z = oc.provision_user(user)

        m.assert_called_with('foo@bar.baz', 'foo', 'bar.baz')
        assert z.endswith('bork')

    def test_okta_provision_user_new_with_name(self):
        """Provisioning a user with a name, uses it"""
        oc = OktaClient('https://okta', 'token')
        m = Mock()
        m.return_value = {'id': 'bork'}
        oc.new_user = m

        user = {
            'name': {
                'givenName': 'First',
                'familyName': 'Last'
            },
            'userName': 'foo@bar.baz'
        }

        z = oc.provision_user(user)

        m.assert_called_with('foo@bar.baz', 'First', 'Last')
        assert z.endswith('bork')

    def test_okta_provision_user_existing(self):
        """Provisioning a user with a name, uses it"""
        oc = OktaClient('https://okta', 'token')

        r = Mock()
        r.text = json.dumps({
            'errorSummary': 'login: An object with this field already exists in the current organization'
        })
        m = Mock()
        m.side_effect = OktaError(r)
        oc.new_user = m

        user = {
            'name': {
                'givenName': 'First',
                'familyName': 'Last'
            },
            'userName': 'foo@bar.baz'
        }

        z = oc.provision_user(user)

        m.assert_called_with('foo@bar.baz', 'First', 'Last')
        assert z.endswith('foo@bar.baz')

    def test_okta_provision_fail(self):
        """Provisioning a user with a name, uses it"""
        oc = OktaClient('https://okta', 'token')

        r = Mock()
        r.text = json.dumps({'errorSummary': 'unexpected'})
        m = Mock()
        m.side_effect = OktaError(r)
        oc.new_user = m

        user = {
            'name': {
                'givenName': 'First',
                'familyName': 'Last'
            },
            'userName': 'foo@bar.baz'
        }

        with self.assertRaises(OktaError):
            oc.provision_user(user)
