Discourse Auth for Pretix
==========================

This is a plugin for `pretix`_. 

Discourse authentication backend for pretix

Access policy
-------------

Any valid Forum account can sign in to Pretix as an attendee. Only exact
``meetup-organisers-{city}`` claims that resolve through the plugin's explicit
city/team mapping receive city team membership. Pretix admins alone manage the
``Ansible Meetup Staff`` team and Pretix's site-wide ``is_staff`` flag; Forum
groups never grant staff access. DiscourseConnect must attest ``confirmed_2fa=true``
for city organisers, Pretix staff-team members, and Pretix staff accounts.

Every login also requires a working Discourse Admin API key so the plugin can
reject silenced or suspended accounts. Organizer team configuration errors block
the affected organizer login; users without organizer claims can still sign in
as attendees. Sessions created by this backend expire after three hours of
inactivity, with Pretix's absolute session limit still applying.

Development setup
-----------------

1. Make sure that you have a working `pretix development setup`_.

2. Clone this repository.

3. Activate the virtual environment you use for pretix development.

4. Execute ``python setup.py develop`` within this directory to register this application with pretix's plugin registry.

5. Execute ``make`` within this directory to compile translations.

6. Restart your local pretix server. You can now use the plugin from this repository for your events by enabling it in
   the 'plugins' tab in the settings.

This plugin has CI set up to enforce a few code style rules. To check locally, you need these packages installed::

    pip install flake8 isort black

To check your plugin for rule violations, run::

    black --check .
    isort -c .
    flake8 .

You can auto-fix some of these issues by running::

    isort .
    black .

To automatically check for these issues before you commit, you can run ``.install-hooks``.


License
-------


Copyright 2026 gundalow

Released under the terms of the Apache License 2.0



.. _pretix: https://github.com/pretix/pretix
.. _pretix development setup: https://docs.pretix.eu/en/latest/development/setup.html
