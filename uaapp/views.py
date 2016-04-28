from datetime import datetime, timedelta
from flask import session, redirect, request, url_for, render_template
from requests.auth import HTTPBasicAuth

import json
import requests

from uaapp import app


@app.before_request
def have_uaa_token():
    """Before each request, make sure we have a valid token from UAA.

    If we don't send them to UAA to start the oauth process.

    Technically we should bounce them through the renew token process if we already have one,
    but this app will be used sparingly, so it's fine to push them back through the authorize flow
    each time we need to renew our token.

    """
    # don't authenticate the oauth code receiver, or we'll never get the code back from UAA
    if request.endpoint == 'oauth_login':
        return

    token = session.get('UAA_TOKEN', None)
    token_expires = session.get('UAA_TOKEN_EXPIRES', None)

    # if we don't have a token, or it's expired we need to do the UAA Oauth dance
    if not token or not token_expires or token_expires < datetime.utcnow():
        return redirect('{0}/oauth/authorize?client_id={1}'.format(
            app.config['UAA_BASE_URL'],
            app.config['UAA_CLIENT_ID']
        ))


@app.route('/logout')
def logout():
    """Destroy the session"""
    session.clear()

    return redirect(url_for('index'))


@app.route('/')
def index():
    """Display a list of users who's origin is 'UAA' as these are the users we want to migrate to
    an external IDP"""

    # TODO: Allow selection of an IDP;  There currently seems to be a problem with assigning
    # the needed idps.read scope to a user via the OAUTH flow.
    # Until that's fixed we set the target IDP in our config file
    # idps = requests.get(
    #         '{0}/identity-providers?active=True'.format(app.config['UAA_BASE_URL']),
    #         verify=app.config['VERIFY_TLS'],
    #         headers={'Authorization': session['UAA_TOKEN']}
    #     ).text

    # return str(idps)

    users = json.loads(
        requests.get(
            '{0}/Users'.format(app.config['UAA_BASE_URL']),
            params={'filter': "origin eq 'uaa'"},
            verify=app.config['VERIFY_TLS'],
            headers={'Authorization': session['UAA_TOKEN']}
        ).text
    )

    return render_template('index.html', users=users['resources'], target_idp=app.config['TARGET_IDP'])


@app.route('/migrate_confirm/<user_id>')
def migrate_confirm(user_id):
    """Ask the user to confirm the migration as once we do this, the migrated account MUST use the IDP"""
    user = json.loads(
        requests.get(
            '{0}/Users/{1}'.format(app.config['UAA_BASE_URL'], user_id),
            verify=app.config['VERIFY_TLS'],
            headers={'Authorization': session['UAA_TOKEN']}
        ).text
    )

    return render_template('migrate_confirm.html', user=user, target_idp=app.config['TARGET_IDP'])


@app.route('/migrate', methods=['POST'])
def migrate():
    """Migrate the User. The steps required:

        1. Grab the User record from UAA
        2. Translate it into an Okta User Record
        3. Create the user in Okta
            3a. TBD: What to do if user already exists in okta? I think ok to ignore?
        4. Update user in UAA changing origin
    """
    user = json.loads(
        requests.get(
            '{0}/Users/{1}'.format(app.config['UAA_BASE_URL'], request.form['user_id']),
            verify=app.config['VERIFY_TLS'],
            headers={'Authorization': session['UAA_TOKEN']}
        ).text
    )

    okta_user = {
        'profile': {
            'email': user['userName'],
            'login': user['userName']
        }
    }

    json.loads(
        requests.post(
            '{0}/api/v1/users'.format(app.config['OKTA_BASE_URL']),
            json=okta_user,
            headers={'Authorization': 'SSWS ' + app.config['OKTA_API_TOKEN']}
        ).text
    )

    # TODO: Verify Okta actually created the user before we flip UAA
    user['origin'] = app.config['TARGET_IDP']

    updated_user = json.loads(
        requests.put(
            '{0}/Users/{1}'.format(app.config['UAA_BASE_URL'], user['id']),
            json=user,
            verify=app.config['VERIFY_TLS'],
            headers={'Authorization': session['UAA_TOKEN'], 'If-Match': user['meta']['version']}
        ).text
    )

    # TODO: Handle error from UAA in updating user

    return render_template('migrate.html', user=updated_user)


@app.route('/oauth/login')
def oauth_login():
    """Called at the end of the oauth flow.  We'll receive an auth code from UAA and use it to
    retrieve a bearer token that we can use to actually do stuff
    """
    url = '{0}/oauth/token'.format(app.config['UAA_BASE_URL'])

    result = json.loads(
        requests.post(
            url,
            {
                'code': request.args['code'],
                'grant_type': 'authorization_code',
                'response_type': 'token'
            },
            verify=app.config['VERIFY_TLS'],
            auth=HTTPBasicAuth(app.config['UAA_CLIENT_ID'], app.config['UAA_CLIENT_SECRET'])
        ).text
    )

    session['UAA_TOKEN'] = 'Bearer ' + result['access_token']
    session['UAA_TOKEN_EXPIRES'] = datetime.utcnow() + timedelta(seconds=result['expires_in'])

    return redirect(url_for('index'))
