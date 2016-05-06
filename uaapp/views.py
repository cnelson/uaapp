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

    users = []
    for uid in request.form.getlist('user_ids'):
        users.append(g.uaac.get_user(uid))

    return render_template(
        'confirm.html',
        users=users,
        userids=[x['id'] for x in users],
        source_idp=request.form['source_idp'],
        target_idp=request.form['target_idp'],
        provision=provision,
        send_email=send_email,
        subject=subject,
        template=template
    )
