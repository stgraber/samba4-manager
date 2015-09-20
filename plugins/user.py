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
from flask import abort, flash, g, render_template, redirect, request
from flask.ext.wtf import EqualTo, Form, PasswordField, Required, \
    SelectMultipleField, TextAreaField, TextField

from libs.ldap_func import ldap_auth, ldap_change_password, \
    ldap_create_entry, ldap_delete_entry, ldap_get_user, \
    ldap_get_membership, ldap_get_group, ldap_in_group, \
    ldap_update_attribute, ldap_user_exists, LDAP_AD_USERACCOUNTCONTROL_VALUES

import ldap


class UserSSHEdit(Form):
    ssh_keys = TextAreaField('SSH keys')


class UserProfileEdit(Form):
    first_name = TextField('First name')
    last_name = TextField('Last name')
    display_name = TextField('Display name')
    user_name = TextField('Username', [Required()])
    mail = TextField('E-mail address')
    uac_flags = SelectMultipleField('User flags', coerce=int)


class UserAdd(UserProfileEdit):
    password = PasswordField('Password', [Required()])
    password_confirm = PasswordField('Repeat password',
                                     [Required(),
                                      EqualTo('password',
                                              message='Passwords must match')])


class PasswordChange(Form):
    password = PasswordField('New password', [Required()])
    password_confirm = PasswordField('Repeat new password',
                                     [Required(),
                                      EqualTo('password',
                                              message='Passwords must match')])


class PasswordChangeUser(PasswordChange):
    oldpassword = PasswordField('Current password', [Required()])


def init(app):
    @app.route('/users/+add', methods=['GET', 'POST'])
    @ldap_auth("Domain Admins")
    def user_add():
        title = "Add user"

        base = request.args.get('base')
        if not base:
            base = "OU=People,%s" % g.ldap['dn']

        form = UserAdd(request.form)
        field_mapping = [('givenName', form.first_name),
                         ('sn', form.last_name),
                         ('displayName', form.display_name),
                         ('sAMAccountName', form.user_name),
                         ('mail', form.mail),
                         (None, form.password),
                         (None, form.password_confirm),
                         ('userAccountControl', form.uac_flags)]

        form.visible_fields = [field[1] for field in field_mapping]

        form.uac_flags.choices = [(key, value[0]) for key, value in
                                  LDAP_AD_USERACCOUNTCONTROL_VALUES.items()
                                  if value[1]]

        if form.validate_on_submit():
            try:
                # Default attributes
                upn = "%s@%s" % (form.user_name.data, g.ldap['domain'])
                attributes = {'objectClass': "user",
                              'UserPrincipalName': upn,
                              'accountExpires': "0",
                              'lockoutTime': "0"}

                for attribute, field in field_mapping:
                    if attribute == 'userAccountControl':
                        current_uac = 512
                        for key, flag in (LDAP_AD_USERACCOUNTCONTROL_VALUES
                                          .items()):
                            if flag[1] and key in field.data:
                                current_uac += key
                        attributes[attribute] = str(current_uac)
                    elif attribute and field.data:
                        attributes[attribute] = field.data

                ldap_create_entry("cn=%s,%s" % (form.user_name.data, base),
                                  attributes)
                ldap_change_password(None, form.password.data,
                                     form.user_name.data)

                flash("User successfully created.", "success")
                return redirect(url_for('user_overview',
                                        username=form.user_name.data))
            except ldap.LDAPError as e:
                error = e.message['info'].split(":", 2)[-1].strip()
                error = str(error[0].upper() + error[1:])
                flash(error, "error")
        elif form.errors:
            flash("Some fields failed validation.", "error")

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Add user",
                               parent=url_for('user_add'))

    @app.route('/user/<username>')
    @ldap_auth("Domain Users")
    def user_overview(username):
        title = "User details - %s" % username

        if not ldap_user_exists(username=username):
            abort(404)

        identity_fields = [('givenName', "First name"),
                           ('sn', "Last name"),
                           ('displayName', "Display name"),
                           ('sAMAccountName', "User name"),
                           ('mail', "E-mail address"),
                           ('___primary_group', "Primary group")]
        group_fields = [('sAMAccountName', "Name"),
                        ('description', "Description")]

        admin = ldap_in_group("Domain Admins")
        user = ldap_get_user(username=username)
        group_details = [ldap_get_group(group, 'distinguishedName')
                         for group in ldap_get_membership(username)]
        user['___primary_group'] = group_details[0]['sAMAccountName']

        groups = sorted(group_details, key=lambda entry:
                        entry['sAMAccountName'])

        return render_template("pages/user_overview.html", g=g, title=title,
                               user=user, identity_fields=identity_fields,
                               group_fields=group_fields,
                               admin=admin, groups=groups,
                               uac_values=LDAP_AD_USERACCOUNTCONTROL_VALUES)

    @app.route('/user/<username>/+changepw', methods=['GET', 'POST'])
    @ldap_auth("Domain Users")
    def user_changepw(username):
        title = "Change password"

        if not ldap_user_exists(username=username):
            abort(404)

        admin = ldap_in_group("Domain Admins")
        if username != g.ldap['username'] and admin:
            form = PasswordChange(request.form)
            form.visible_fields = []
        else:
            form = PasswordChangeUser(request.form)
            form.visible_fields = [form.oldpassword]

        form.visible_fields += [form.password, form.password_confirm]

        if form.validate_on_submit():
            try:
                if username != g.ldap['username'] and admin:
                    ldap_change_password(None,
                                         form.password.data,
                                         username=username)
                else:
                    ldap_change_password(form.oldpassword.data,
                                         form.password.data,
                                         username=username)
                flash("Password changed successfuly.", "success")
                return redirect(url_for('user_overview', username=username))
            except ldap.LDAPError as e:
                error = e.message['info'].split(":", 2)[-1].strip()
                error = str(error[0].upper() + error[1:])
                flash(error, "error")
        elif form.errors:
                flash("Some fields failed validation.", "error")

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Change password",
                               parent=url_for('user_overview',
                                              username=username))

    @app.route('/user/<username>/+delete', methods=['GET', 'POST'])
    @ldap_auth("Domain Admins")
    def user_delete(username):
        title = "Delete user"

        if not ldap_user_exists(username=username):
            abort(404)

        form = Form(request.form)

        if form.validate_on_submit():
            try:
                user = ldap_get_user(username=username)
                ldap_delete_entry(user['distinguishedName'])
                flash("User successfuly deleted.", "success")
                return redirect(url_for('core_index'))
            except ldap.LDAPError as e:
                error = e.message['info'].split(":", 2)[-1].strip()
                error = str(error[0].upper() + error[1:])
                flash(error, "error")
        elif form.errors:
                flash("Some fields failed validation.", "error")

        return render_template("pages/user_delete.html", title=title,
                               action="Delete user", form=form,
                               username=username,
                               parent=url_for('user_overview',
                                              username=username))

    @app.route('/user/<username>/+edit-profile', methods=['GET', 'POST'])
    @ldap_auth("Domain Admins")
    def user_edit_profile(username):
        title = "Edit user"

        if not ldap_user_exists(username=username):
            abort(404)

        user = ldap_get_user(username=username)
        form = UserProfileEdit(request.form)
        field_mapping = [('givenName', form.first_name),
                         ('sn', form.last_name),
                         ('displayName', form.display_name),
                         ('sAMAccountName', form.user_name),
                         ('mail', form.mail),
                         ('userAccountControl', form.uac_flags)]

        form.uac_flags.choices = [(key, value[0]) for key, value in
                                  LDAP_AD_USERACCOUNTCONTROL_VALUES.items()
                                  if value[1]]

        form.visible_fields = [field[1] for field in field_mapping]

        if form.validate_on_submit():
            try:
                for attribute, field in field_mapping:
                    value = field.data
                    if value != user.get(attribute):
                        if attribute == 'sAMAccountName':
                            # Rename the account
                            ldap_update_attribute(user['distinguishedName'],
                                                  "sAMAccountName", value)
                            ldap_update_attribute(user['distinguishedName'],
                                                  "userPrincipalName",
                                                  "%s@%s" % (value,
                                                             g.ldap['domain']))
                            # Finish by renaming the whole record
                            ldap_update_attribute(user['distinguishedName'],
                                                  "cn", value)
                            user = ldap_get_user(value)
                        elif attribute == 'userAccountControl':
                            current_uac = user['userAccountControl']
                            for key, flag in (LDAP_AD_USERACCOUNTCONTROL_VALUES
                                              .items()):
                                if not flag[1]:
                                    continue

                                if key in value:
                                    if not current_uac & key:
                                        current_uac += key
                                else:
                                    if current_uac & key:
                                        current_uac -= key
                            ldap_update_attribute(user['distinguishedName'],
                                                  attribute, str(current_uac))
                        else:
                            ldap_update_attribute(user['distinguishedName'],
                                                  attribute, value)

                flash("Profile successfully updated.", "success")
                return redirect(url_for('user_overview',
                                        username=form.user_name.data))
            except ldap.LDAPError as e:
                error = e.message['info'].split(":", 2)[-1].strip()
                error = str(error[0].upper() + error[1:])
                flash(error, "error")
        elif form.errors:
            flash("Some fields failed validation.", "error")

        if not form.is_submitted():
            form.first_name.data = user.get('givenName')
            form.last_name.data = user.get('sn')
            form.display_name.data = user.get('displayName')
            form.user_name.data = user.get('sAMAccountName')
            form.mail.data = user.get('mail')
            form.uac_flags.data = [key for key, flag in
                                   LDAP_AD_USERACCOUNTCONTROL_VALUES.items()
                                   if (flag[1] and
                                       user['userAccountControl'] & key)]

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Save changes",
                               parent=url_for('user_overview',
                                              username=username))

    @app.route('/user/<username>/+edit-ssh', methods=['GET', 'POST'])
    @ldap_auth("Domain Admins")
    def user_edit_ssh(username):
        title = "Edit SSH keys"

        if not ldap_user_exists(username=username):
            abort(404)

        user = ldap_get_user(username=username)

        form = UserSSHEdit(request.form)
        form.visible_fields = [form.ssh_keys]

        if form.validate_on_submit():
            new_entries = [entry.strip() for entry in
                           form.ssh_keys.data.split("\n")]
            try:
                ldap_update_attribute(user['distinguishedName'],
                                      'sshPublicKey', new_entries,
                                      'ldapPublicKey')
                flash("SSH keys successfuly updated.", "success")
                return redirect(url_for('user_overview', username=username))
            except ldap.LDAPError as e:
                error = e.message['info'].split(":", 2)[-1].strip()
                error = str(error[0].upper() + error[1:])
                flash(error, "error")
        elif form.errors:
            flash("Some fields failed validation.", "error")

        if not form.is_submitted():
            if 'sshPublicKey' in user:
                form.ssh_keys.data = "\n".join(user['sshPublicKey'])

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Save changes",
                               parent=url_for('user_overview',
                                              username=username))
