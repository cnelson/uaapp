# This is your Flask secret key, used for sessions
SECRET_KEY = 'Generate a good key: http://flask.pocoo.org/docs/0.10/quickstart/#sessions'

# The base URL to your UAA instance
UAA_BASE_URL = 'https://uaa.bosh-lite.com'

# The UAA client id and secret.  Create this with:
# $ uaac client add client_id
# --name "A description for your client"
# --scope "idps.read scim.read scim.write"
# --authorized_grant_types "authorization_code"
# --redirect_uri https://path-to-this-flask-app/oauth/login
# -s client_secret
UAA_CLIENT_ID = 'your-client-id'
UAA_CLIENT_SECRET = 'your-client-secret'

# Validate certs when talking to UAA?
VERIFY_TLS = False

# The target IDP / origin to migrate users to
# This needs to match the key of the provider in your login.yml
# saml:
#     providers:
#         *TARGET_IDP*:
#           idpMetadata:
#           ...

TARGET_IDP = 'okta'

# The URL to your OKTA instance
OKTA_BASE_URL = 'https://<something>.oktapreview.com'
# http://developer.okta.com/docs/api/getting_started/getting_a_token.html
OKTA_API_TOKEN = 'your-token-here'
