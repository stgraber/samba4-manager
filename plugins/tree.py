# -*- coding: utf-8 -*-

# Copyright (C) 2012-2015 Stéphane Graber
# Author: Stéphane Graber <stgraber@ubuntu.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You can find the license on Debian systems in the file
# /usr/share/common-licenses/GPL-2

from libs.common import iri_for as url_for
from flask import g, render_template
from libs.ldap_func import ldap_auth, ldap_get_entries, ldap_in_group

TREE_BLACKLIST = ["CN=ForeignSecurityPrincipals",
                  "OU=sudoers"]


def init(app):
    @app.route('/tree')
    @app.route('/tree/<base>')
    @ldap_auth("Domain Users")
    def tree_base(base=None):

        if not base:
            base = g.ldap['dn']
        elif not base.lower().endswith(g.ldap['dn'].lower()):
            base += ",%s" % g.ldap['dn']

        admin = ldap_in_group("Domain Admins")
        entry_fields = [('name', "Name"),
                        ('__description', "Description"),
                        ('__type', "Type")]

        entries = []
        for entry in sorted(ldap_get_entries("objectClass=top", base,
                            "onelevel"), key=lambda entry: entry['name']):
            if 'description' not in entry:
                if 'displayName' in entry:
                    entry['__description'] = entry['displayName']
            else:
                entry['__description'] = entry['description']

            entry['__target'] = url_for('tree_base',
                                        base=entry['distinguishedName'])
            if 'user' in entry['objectClass']:
                entry['__type'] = "User"
                entry['__target'] = url_for('user_overview',
                                            username=entry['sAMAccountName'])
            elif 'group' in entry['objectClass']:
                entry['__type'] = "Group"
                entry['__target'] = url_for('group_overview',
                                            groupname=entry['sAMAccountName'])
            elif 'organizationalUnit' in entry['objectClass']:
                entry['__type'] = "Organizational Unit"
            elif 'container' in entry['objectClass']:
                entry['__type'] = "Container"
            elif 'builtinDomain' in entry['objectClass']:
                entry['__type'] = "Built-in"
            else:
                entry['__type'] = "Unknown"

            if 'showInAdvancedViewOnly' in entry \
               and entry['showInAdvancedViewOnly']:
                continue

            for blacklist in TREE_BLACKLIST:
                if entry['distinguishedName'].startswith(blacklist):
                    break
            else:
                entries.append(entry)

        parent = None
        base_split = base.split(',')
        if not base_split[0].lower().startswith("dc"):
            parent = ",".join(base_split[1:])

        return render_template("pages/tree_base.html", parent=parent,
                               admin=admin, base=base, entries=entries,
                               entry_fields=entry_fields)
