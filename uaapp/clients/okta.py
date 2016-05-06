"""A minimal wrapper for the Okta API.
http://developer.okta.com/docs/api/getting_started/design_principles.html

The offical python client from okta appears to be abandoned ( https://github.com/okta/oktasdk-python/issues )
so this wrapper only implements the bare minimum we require
"""

from posixpath import join as urljoin
import json
import requests


class OktaError(RuntimeError):
    """This exception is raised when the Okta API returns a status code >= 400

    Attributes:
        response:   The full response object from requests that was returned
        error:  The body of the response json decoded

    Args:
        response: The full response object that is causing this exception to be raised

    """
    def __init__(self, response):
        self.response = response
        self.error = json.loads(response.text)

        try:
            # make our value, the first problem cause if it exist
            message = self.error['errorCauses'][0]['errorSummary']
        except (KeyError, IndexError):
            # if not, then use the generic (usually less helpful) summary
            message = self.error['errorSummary']

        super(OktaError, self).__init__(message)


class OktaClient(object):
    """A minimal client for the Okta API

    Args:
        base_url: The URL to your Okta instance
        token: An API Token to authenticate
            http://developer.okta.com/docs/api/getting_started/getting_a_token.html
        api_version: The version of the API to use.
            Currently only 'v1' is supported
    """
    def __init__(self, base_url, token, api_version='v1'):
        self.base_url = base_url
        self.token = token
        self.api_version = api_version

    def _request(self, resource, method, body=None):
        """Make a request to the Okta API.

        Args:
            resource: The API method you wish to call (example: '/users')
            method: The method to use when making the request GET/POST/etc
            body (optional): An json encodeable object which will be included as the body
            of the request

        Raises:
            OktaError: An error occured making the request

        Returns:
            dict:   The parsed json response

        """
        # build our URL from all the pieces given to us
        endpoint = urljoin(
            self.base_url,
            'api',
            self.api_version,
            resource.lstrip('/')
        )

        # convert 'POST' to requests.post
        requests_method = getattr(requests, method.lower())

        # make the request
        response = requests_method(
            endpoint,
            json=body,
            headers={
                'Authorization': 'SSWS ' + self.token
            }
        )

        # if we errored raise an exception
        if response.status_code >= 400:
            raise OktaError(response)

        # return the response
        return json.loads(response.text)

    def new_user(self, email, first_name, last_name):
        """Create a new user with minimal details

        Args:
            email: The email address (and login) for this user
            first_name: The first name for the user
            last_name: The last name for the user

        Raises:
            OktaError: There was an error creating the user

        Returns:
            dict:   An object describing the created user

        """
        okta_user = {
            'profile': {
                'email': email,
                'login': email,
                'firstName': first_name,
                'lastName': last_name
            }
        }

        return self._request('/users', 'POST', body=okta_user)

    def provision_user(self, user):
        """Create a user and return the URL to the created resource

        Args:
            user(dict): A dict in the format returned by a call to uaapp.clients.uaa.UAAClient.get_user()

        Raises:
            OktaError: There was an error creating the user

        Returns:
            str: The url to the created resource

        """

        try:
            first_name = user['name']['givenName']
            if not first_name:
                raise KeyError
        except KeyError:
            first_name = user['userName'].split('@', 1)[0]

        try:
            last_name = user['name']['familyName']
            if not last_name:
                raise KeyError
        except KeyError:
            last_name = user['userName'].split('@', 1)[1]

        try:
            # create the user in okta
            okta_user = self.new_user(user['userName'], first_name, last_name)
            user_id = okta_user['id']
        except OktaError as exc:
            # this is gross, but Okta returns the same error for all validation fails
            # If the user is already in Okta under this email, we'll consider them migrated
            # TODO: Validate this decision

            if str(exc) == 'login: An object with this field already exists in the current organization':
                user_id = user['userName']
            else:
                raise

        return urljoin(
            self.base_url,
            'api',
            self.api_version,
            'users',
            user_id
        )
