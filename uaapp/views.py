from flask import Blueprint
# , session, redirect, url_for

ui = Blueprint('ui', __name__)


@ui.route('/')
def index():
    return 'UI INDEX'

# @ui.route('/logout')
# def logout():
#   session.clear()

#   return redirect(url_for('ui.index'))
