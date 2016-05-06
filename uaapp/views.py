from flask import Blueprint, session, redirect, url_for, render_template, g, current_app, request

ui = Blueprint('ui', __name__)


@ui.route('/')
def index():
    return render_template('index.html', idps=g.uaac.idps(), providers=current_app.config['PROVIDERS'].keys())


@ui.route('/logout')
def logout():
    session.clear()

    return redirect(url_for('ui.index'))


@ui.route('/confirm', methods=['POST'])
def confirm():
    subject = request.form.get('subject', False)
    template = request.form.get('template', False)
    send_email = bool(subject and template)

    provision = request.form.get('provision', False)
    if not provision:
        # if provision is blank, then be explicit
        provision = False

    user_ids = request.form.getlist('user_ids')

    return """
    Users: {4}<br>
    send_email: {2} ({0}, {1})<br>
    provision: {3}<br>
    """.format(subject, template, send_email, provision, user_ids)
