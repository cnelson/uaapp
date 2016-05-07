from datetime import datetime, timedelta
try:
    import urlparse
except ImportError:  # py3 # pragma: no cover
    from urllib import parse as urlparse

from flask import Flask, redirect, url_for, request, session, g

from uaapp.api import v1
from uaapp.views import ui
from uaapp.clients import UAAClient, OktaClient


def create_app():
    """Create an instance of the web application"""
    # setup our app config
    app = Flask(__name__)
    app.config.from_object('uaapp.default_settings')

    try:
        app.config.from_object('uaapp.settings')
    except ImportError:
        pass

    try:
        app.config.from_envvar('UAAPP_SETTINGS')
    except (OSError, RuntimeError):
        pass

    app.config['PROVIDERS'] = {}

    # activate the Okta provider if we have the info
    try:
        app.config['PROVIDERS'][urlparse.urlparse(app.config['OKTA_BASE_URL']).netloc] = OktaClient(
            app.config['OKTA_BASE_URL'],
            app.config['OKTA_API_TOKEN']
        )
    except KeyError:
        pass

    # connect the API and frontend
    app.register_blueprint(ui)
    app.register_blueprint(v1, url_prefix='/api/v1')

    # set the default API version
    @app.route('/api')
    @app.route('/api/')
    def api_default():
        return redirect(url_for('api_v1.index'))

    # handle oauth
    @app.before_request
    def have_uaa_token():
        """Before each request, make sure we have a valid token from UAA.

        If we don't send them to UAA to start the oauth process.

        Technically we should bounce them through the renew token process if we already have one,
        but this app will be used sparingly, so it's fine to push them back through the authorize flow
        each time we need to renew our token.

        """

        # don't authenticate the oauth code receiver, or we'll never get the code back from UAA
        if request.endpoint and request.endpoint == 'oauth_login':
            return

        # check our token, and expirary date
        token = session.get('UAA_TOKEN', None)
        token_expires = session.get('UAA_TOKEN_EXPIRES', None)

        # if all looks good, setup the client
        if token and token_expires and token_expires > datetime.utcnow():
            g.uaac = UAAClient(app.config['UAA_BASE_URL'], session['UAA_TOKEN'], verify_tls=app.config['VERIFY_TLS'])
        else:
            # if not forget the token, it's bad (if we have one)
            session.clear()

            # if we aren't an API request, then start the oauth flow
            # if we are, do nothing, the API will raise a 403, when g.uaac doesn't exist
            if not request.endpoint.startswith('api'):
                return redirect('{0}/oauth/authorize?client_id={1}'.format(
                    app.config['UAA_BASE_URL'],
                    app.config['UAA_CLIENT_ID']
                ))

    @app.route('/oauth/login')
    def oauth_login():
        """Called at the end of the oauth flow.  We'll receive an auth code from UAA and use it to
        retrieve a bearer token that we can use to actually do stuff
        """

        uaac = UAAClient(app.config['UAA_BASE_URL'], None, verify_tls=app.config['VERIFY_TLS'])
        token = uaac.oauth_token(request.args['code'], app.config['UAA_CLIENT_ID'], app.config['UAA_CLIENT_SECRET'])

        session['UAA_TOKEN'] = token['access_token']
        session['UAA_TOKEN_EXPIRES'] = datetime.utcnow() + timedelta(seconds=token['expires_in'])
        session['UAA_TOKEN_SCOPES'] = token['scope'].split(' ')

        return redirect(url_for('ui.index'))

    return app
