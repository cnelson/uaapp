"""UAAPP v1 API.

This is an UNSTABLE API and endpoints and parameters are likely to change.

The methods provided here are intended to support the migration of users between UAA and external
IDPs.  This is not intended to be a complete API interface to UAA or any external IDP


Note:
    This blueprint expects that the UAAC oauth flow has already been completed, and that
    g.uaac has been initialized to a uaapp.clients.uaa.UAAClient
"""

import smtplib

from flask import Blueprint, current_app, render_template, jsonify, g, request, Response
from jinja2 import Template, TemplateError
from email.mime.text import MIMEText

from uaapp.clients import UAAError

v1 = Blueprint('api_v1', __name__)


class APIError(Exception):
    """A Generic class for API errors

    Attributes:
        status_code(int): The HTTP status code to return
        message(str): The error messsage to return
    """
    status_code = 500
    message = 'An Unknown error has occured.'

    def __init__(self, message=None):
        """Construct an error message.

        Args:
            message(str, optional): If provided, override the default error messaging
        """
        if message:
            self.message = message


class UnauthorizedError(APIError):
    status_code = 403
    message = 'An oauth token for UAA was not available'


class BadGatewayError(APIError):
    status_code = 502
    message = 'The server was acting as a gateway or proxy and received an invalid response from the upstream server'


class BadRequestError(APIError):
    status_code = 400
    message = 'The server cannot or will not process the request due to an apparent client error'


class NotFoundError(APIError):
    status_code = 404
    message = 'The requested resource could not be found'


class NotImplementedError(APIError):
    status_code = 501
    message = 'The server is unable to fulfill the request'


@v1.errorhandler(APIError)
def report_error(error):
    """Any APIError that is raised will land here.

    We convert the exception to a json response and deliver it to the caller
    """
    response = jsonify({'error_message': error.message})
    response.status_code = error.status_code
    return response


# TODO: Allow API callers to pass bearer token to us in a header which will be forwarded upstream
@v1.before_request
def check_uaac():
    """Ensure our UAAClient exists before the API methods are invoked"""

    # no auth checking if they just want to read docs
    if request.endpoint == v1.name + '.index':
        return

    try:
        g.uaac
    except AttributeError:
        raise UnauthorizedError()


@v1.route('/')
def index():
    """Returns the contents of this document"""
    return Response(render_template('api/v1/index.html'), mimetype='text/plain')


@v1.route('/idps')
def list_idps():
    """Return a list of *active* IDPs from UAA

    Method: GET

    Parameters: None

    Returns:
        200: json object listing the IDPs
        502: UAA responded with an error
    """

    try:
        # the idps api just returns a list, so we make it similar to the /users response
        # where the contents are under 'resources', so jsonify doesn't flip out
        # hopefully this will get fixed upstream
        return jsonify({'resources': g.uaac.idps(active_only=True)})
    except UAAError as exc:
        raise BadGatewayError(str(exc))


@v1.route('/users')
def list_users():
    """Return a list of users optionally filtered by the following params:

    Method: GET

    Parameters:
        origin: Return only users who's origin matches
        domain: Return only users who's domain matches

        Specifying both parameters is alllowed; this produces an AND query


    Returns:
        200: json object listing the users
        502: UAA responded with an error
    """

    filters = []

    # are we filtering by origin?
    try:
        filters.append('origin eq "{0}"'.format(request.args['origin']))
    except KeyError:
        pass

    # or domain?
    try:
        filters.append('userName co "{0}"'.format(request.args['domain']))
    except KeyError:
        pass

    # if we have filters, then join them, else set to None
    if filters:
        filters = ' and '.join(filters)
    else:
        filters = None

    try:
        results = g.uaac.users(filters)

        # if they asked us to filter by domain, we need to do an extra step
        # as SCIM only allows us to filter by 'contains' not 'ends with'
        # this step ensures we only return users who username ends with the requested domain
        # this will avoid the possible case of something having an email like example.com@something-else.com
        results['resources'] = [x for x in results['resources'] if x['userName'].endswith(request.args['domain'])]
    except UAAError as exc:
        raise BadGatewayError(str(exc))
    except KeyError:
        # we land here if the list comprehension above fails do to request.args['domain'] not existing
        pass

    return jsonify(results)


@v1.route('/migrate', methods=['POST'])
def migrate_user():
    """Update a user's origin to a different provider

    Method: POST

    Parameters:
        id: The UAA user id of the user to migrate
        origin: The new origin for the user

    Returns:
        200: json object describing the migrated user
        400: A required parameter (id or origin) was missing from the request
        404: The user_id or origin provided does not exist
        502: UAA raised an error when attempting to update the user's origin

    """

    # make sure the user is valid
    try:
        user_id = request.form['id']
        user = g.uaac.get_user(user_id)
    except KeyError:
        raise BadRequestError('id is a required parameter')
    except UAAError:
        raise NotFoundError('{0} is an invalid user id'.format(user_id))

    # and the origin
    try:
        origin_key = request.form['origin']
    except KeyError:
        raise BadRequestError('origin is a required parameter')

    if origin_key not in [x['originKey'] for x in g.uaac.idps(active_only=True)]:
        raise NotFoundError('{0} is an invalid origin'.format(origin_key))

    try:
        user['origin'] = origin_key
        return jsonify(g.uaac.put_user(user))
    except UAAError as exc:
        raise BadGatewayError(str(exc))


@v1.route('/provision', methods=['POST'])
def provision_user():
    """Copy a user from UAA to an external provider

    Method: POST

    Parameters:
        id: The UAA user id of the user that will be copied to an external IDP
        provider: The exteral IDP

    Returns:
        201: The user was provisioned in the external provider, the Location: header will reference the new resource
        400: A required parameter (id or provider) was missing from the request
        404: The user_id or provider does not exist
        502: UAA raised an error when attempting to update the user's origin

    """

    # don't bother hitting any APIs if we don't have any registered providers
    if not current_app.config['PROVIDERS']:
        raise NotImplementedError('No providers are registered')

    # ensure the provided is valid
    try:
        pid = request.form['provider']
    except KeyError:
        raise BadRequestError('provider is a required parameter')
    try:
        provider = current_app.config['PROVIDERS'][pid]
    except KeyError:
        raise NotFoundError('{0} is an invalid provider'.format(pid))

    # and the user
    try:
        user_id = request.form['id']
        user = g.uaac.get_user(user_id)
    except KeyError:
        raise BadRequestError('id is a required parameter')
    except UAAError:
        raise NotFoundError('{0} is an invalid user id'.format(user_id))

    # let the provider do the work
    try:
        location = provider.provision_user(user)
        return '', 201, {'location': location}
    except Exception as exc:  # NOQA:
        raise BadGatewayError(str(exc))


@v1.route('/email', methods=['POST'])
def email_user():
    """Send a notification email to a user

    Method: POST

    Parameters:
        id: The UAA user id of the user who will receive the temail
        subject: The subject of the email
        body: The body of the email
        send: If set, the email will be delivered, if not, a preview will be returned

        The subject and body are processed as Jinja2 templates, with the user's details
        available as 'user' for use in the template.  For example: "Hello {{user.userName}}"
        would inject the user's userName field into the output.

    Returns:
        200: A preview of the email to be sent
        202: The email was queued for delivery
        400: A required parameter (id, subject, body) was missing from the request, or the
            subject or body templates could not be rendered.
        404: The user_id does not exist
        502: Unable to queue the email for delivery
    """

    # make sure the user exists
    try:
        user_id = request.form['id']
        user = g.uaac.get_user(user_id)
    except KeyError:
        raise BadRequestError('id is a required parameter')
    except UAAError:
        raise NotFoundError('{0} is an invalid user id'.format(user_id))

    # and the subject is a valid template
    try:
        t = Template(request.form['subject'])
        subject = t.render(user=user)
    except KeyError:
        raise BadRequestError('subject is a required parameter')
    except TemplateError as exc:
        raise BadRequestError(str(exc))

    # same for the body
    try:
        t = Template(request.form['body'])
        body = t.render(user=user)
    except KeyError:
        raise BadRequestError('body is a required parameter')
    except TemplateError as exc:
        raise BadRequestError(str(exc))

    # have python generate the email for us
    # TODO: I believe this is 7bit by default, think about support for 8bit / multipart messags?
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = '{0} <{1}>'.format(current_app.config['SMTP_FROM_NAME'], current_app.config['SMTP_FROM_ADDR'])
    msg['To'] = user['userName']

    # if we are just generating a preview, then return it
    if 'send' not in request.form:
        return Response(msg.as_string(), mimetype='text/plain')

    # attempt to deliver the message
    try:
        s = smtplib.SMTP(current_app.config['SMTP_HOST'], current_app.config['SMTP_PORT'])
        s.sendmail(current_app.config['SMTP_FROM_ADDR'], [msg['To']], msg.as_string())
        s.quit()
    except Exception as exc:  # NOQA
        raise APIError(str(exc))

    # it's out of our hands now
    return '', 202
