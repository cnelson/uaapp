from flask import Flask

import uaapp.views  # NOQA

app = Flask(__name__)
app.config.from_object('uaapp.default_settings')

try:
    app.config.from_envvar('UAAPP_SETTINGS')
except RuntimeError:
    pass
