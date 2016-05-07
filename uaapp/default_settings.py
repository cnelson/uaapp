# This is your Flask secret key, used for sessions
SECRET_KEY = 'Generate a good key: http://flask.pocoo.org/docs/0.10/quickstart/#sessions'

# The base URL to your UAA instance
UAA_BASE_URL = 'https://uaa.bosh-lite.com'

# The UAA client id and secret.  Create this with:
# The client most have the scopes: idps.read, scim.read, scim.write
UAA_CLIENT_ID = 'your-client-id'
UAA_CLIENT_SECRET = 'your-client-secret'

# Validate certs when talking to UAA?
VERIFY_TLS = False

# The URL to your OKTA instance, if set will enable account migration to Okta
# http://developer.okta.com/docs/api/getting_started/getting_a_token.html
# OKTA_BASE_URL = 'https://<something>.oktapreview.com'
# OKTA_API_TOKEN = 'your-token-here'

# This SMTP server will be used to deliver emails
# These variables DO NOT need to be set, if you do not want to use the email functions
SMTP_FROM_NAME = 'UAAPP'
SMTP_FROM_ADDR = 'no-reply@example.com'
SMTP_HOST = 'localhost'
SMTP_PORT = 2525
