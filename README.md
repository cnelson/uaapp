# UAA Plus Plus
## Utilities for UAA

This application leverages the [UAA API](https://github.com/cloudfoundry/uaa/blob/master/docs/UAA-APIs.rst) to provide additional user managment capabilities not included in the default UAA UI.

### Features:

#### Migrate users between external IDPs and UAA.

UAAPP can update a user's `origin` in UAA so existing users in UAA can be associated with an external IDP

If that external IDP is [Okta](https://www.okta.com/) new accounts can automatically be provisioned during the migration.

UAAPP can also generate and send notification emails to users as part of the migration process.

### Installing the App

#### Step One: Determine the URL for your instance of UAAPP

You'll need to know where the app is going to be hosted, so you can tell UAA about it in the next step.

For example, if you'll be deploying into Cloudfoundry on BOSH-lite your url would probably be http://uaapp.bosh-lite.com/


#### Step Two: Create a client in UAA for this app

This application uses oauth to perform actions on your behalf in UAA.  To add a new oauth client in UAA, run the following command:

	uaac client add [your-client-id] --name "UAA Plus Plus" --scope "idps.read scim.read scim.write" --authorized_grant_types "authorization_code" --redirect_uri [url-from-step-one]/oauth/login -s [your-client-secret]

Remember the client-id and client-secret, you'll need them in the next step

#### Step Three: Configure the app

Copy the default settings, and edit as neccesary:

	cp uaapp/default_settings.py uaapp/settings.py

	vi uaapp/settings.py

#### Step Four: Ensure your UAA user has the proper scopes/groups

Your UAA user must have the scim.read, scim.write, idps.read scopes/group memberships

	uaac member add scim.read [your-uaa-login]
	uaac member add scim.write [your-uaa-login]
	uaac member add idps.read [your-uaa-login]

#### Step Five: Launch the app

This app was designed to run in Cloud Foundry:

	cf push

You can also run it locally in debug mode:

	./run.py

### Contributing 

Ensure any new functionality comes with tests.

Use [tox](http://tox.readthedocs.io/en/latest/) to run the current test suite.
