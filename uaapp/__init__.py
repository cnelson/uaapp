from flask import Flask

app = Flask(__name__)
app.config.from_object('uaapp.default_settings')

import uaapp.views  # NOQA

try:
    app.config.from_envvar('UAAPP_SETTINGS')
except RuntimeError:
    pass
