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
from flask_wtf import FlaskForm
from wtforms import RadioField, TextAreaField, StringField
from wtforms.validators import DataRequired

from libs.ldap_func import ldap_auth, ldap_create_entry, ldap_delete_entry, \
    ldap_get_entry_simple, ldap_get_members, ldap_get_membership, \
    ldap_get_group, ldap_in_group, ldap_update_attribute, ldap_group_exists, \
    LDAP_AD_GROUPTYPE_VALUES

import ldap
import struct


class GroupAddMembers(FlaskForm):
    new_members = TextAreaField('New members')


class GroupEdit(FlaskForm):
    name = StringField('Name', [DataRequired()])
    description = StringField('Description')
    group_type = RadioField('Type',
                            choices=[(2147483648, 'Security group'),
                                     (0, 'Distribution list')],
                            coerce=int)
    group_flags = RadioField('Scope', coerce=int)


def init(app):
    @app.route('/groups/+add', methods=['GET', 'POST'])
    @ldap_auth("Domain Admins")
    def group_add():
        title = "Add group"

        base = request.args.get('base')
        if not base:
            base = "OU=People,%s" % g.ldap['dn']

        form = GroupEdit(request.form)
        field_mapping = [('sAMAccountName', form.name),
                         ('description', form.description),
                         (None, form.group_type),
                         ('groupType', form.group_flags)]

        form.visible_fields = [field[1] for field in field_mapping]

        form.group_flags.choices = [(key, value[0]) for key, value in
                                    LDAP_AD_GROUPTYPE_VALUES.items()
                                    if value[1]]

        if form.validate_on_submit():
            try:
                # Default attributes
                attributes = {'objectClass': "group"}

                for attribute, field in field_mapping:
                    if attribute == "groupType":
                        group_type = int(form.group_type.data) + \
                            int(form.group_flags.data)
                        attributes[attribute] = str(
                            struct.unpack("i",
                                          struct.pack("I",
                                                      int(group_type)))[0])
                    elif attribute and field.data:
                        attributes[attribute] = field.data

                ldap_create_entry("cn=%s,%s" % (form.name.data, base),
                                  attributes)

                flash("Group successfully created.", "success")
                return redirect(url_for('group_overview',
                                        groupname=form.name.data))
            except ldap.LDAPError as e:
                error = e.message['info'].split(":", 2)[-1].strip()
                error = str(error[0].upper() + error[1:])
                flash(error, "error")
        elif form.errors:
            flash("Some fields failed validation.", "error")

        if not form.is_submitted():
            form.group_type.data = 2147483648
            form.group_flags.data = 2

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Add group",
                               parent=url_for('group_add'))

    @app.route('/group/<groupname>')
    @ldap_auth("Domain Users")
    def group_overview(groupname):
        title = "Group details - %s" % groupname

        if not ldap_group_exists(groupname=groupname):
            abort(404)

        identity_fields = [('sAMAccountName', "Name"),
                           ('description', "Description")]

        group_fields = [('sAMAccountName', "Name"),
                        ('description', "Description")]

        group = ldap_get_group(groupname=groupname)
        admin = ldap_in_group("Domain Admins") and not group['groupType'] & 1
        group_details = [ldap_get_group(entry, 'distinguishedName')
                         for entry in ldap_get_membership(groupname)]

        groups = sorted(group_details, key=lambda entry:
                        entry['sAMAccountName'])

        member_list = []
        for entry in ldap_get_members(groupname):
            member = ldap_get_entry_simple({'distinguishedName': entry})
            if 'sAMAccountName' not in member:
                continue
            member_list.append(member)

        members = sorted(member_list, key=lambda entry:
                         entry['sAMAccountName'])

        return render_template("pages/group_overview.html", g=g, title=title,
                               group=group, identity_fields=identity_fields,
                               group_fields=group_fields, admin=admin,
                               groups=groups, members=members,
                               grouptype_values=LDAP_AD_GROUPTYPE_VALUES)

    @app.route('/group/<groupname>/+delete', methods=['GET', 'POST'])
    @ldap_auth("Domain Admins")
    def group_delete(groupname):
        title = "Delete group"

        if not ldap_group_exists(groupname):
            abort(404)

        form = FlaskForm(request.form)

        if form.validate_on_submit():
            try:
                group = ldap_get_group(groupname=groupname)
                ldap_delete_entry(group['distinguishedName'])
                flash("Group successfuly deleted.", "success")
                return redirect(url_for('core_index'))
            except ldap.LDAPError as e:
                error = e.message['info'].split(":", 2)[-1].strip()
                error = str(error[0].upper() + error[1:])
                flash(error, "error")
        elif form.errors:
                flash("Some fields failed validation.", "error")

        return render_template("pages/group_delete.html", title=title,
                               action="Delete group", form=form,
                               groupname=groupname,
                               parent=url_for('group_overview',
                                              groupname=groupname))

    @app.route('/group/<groupname>/+edit', methods=['GET', 'POST'])
    @ldap_auth("Domain Admins")
    def group_edit(groupname):
        title = "Edit group"

        if not ldap_group_exists(groupname):
            abort(404)

        group = ldap_get_group(groupname)

        # We can't edit system groups
        if group['groupType'] & 1:
            abort(401)

        form = GroupEdit(request.form)
        field_mapping = [('sAMAccountName', form.name),
                         ('description', form.description),
                         (None, form.group_type),
                         ('groupType', form.group_flags)]

        form.visible_fields = [field[1] for field in field_mapping]

        form.group_flags.choices = [(key, value[0]) for key, value in
                                    LDAP_AD_GROUPTYPE_VALUES.items()
                                    if value[1]]

        if form.validate_on_submit():
            try:
                for attribute, field in field_mapping:
                    value = field.data
                    if value != group.get(attribute):
                        if attribute == 'sAMAccountName':
                            # Rename the account
                            ldap_update_attribute(group['distinguishedName'],
                                                  "sAMAccountName", value)
                            # Finish by renaming the whole record
                            ldap_update_attribute(group['distinguishedName'],
                                                  "cn", value)
                            group = ldap_get_group(value)
                        elif attribute == "groupType":
                            group_type = int(form.group_type.data) + \
                                int(form.group_flags.data)
                            ldap_update_attribute(
                                group['distinguishedName'], attribute,
                                str(
                                    struct.unpack(
                                        "i", struct.pack(
                                            "I", int(group_type)))[0]))
                        elif attribute:
                            ldap_update_attribute(group['distinguishedName'],
                                                  attribute, value)

                flash("Group successfully updated.", "success")
                return redirect(url_for('group_overview',
                                        groupname=form.name.data))
            except ldap.LDAPError as e:
                error = e.message['info'].split(":", 2)[-1].strip()
                error = str(error[0].upper() + error[1:])
                flash(error, "error")
        elif form.errors:
            flash("Some fields failed validation.", "error")

        if not form.is_submitted():
            form.name.data = group.get('sAMAccountName')
            form.description.data = group.get('description')
            form.group_type.data = group['groupType'] & 2147483648
            form.group_flags.data = 0
            for key, flag in LDAP_AD_GROUPTYPE_VALUES.items():
                if flag[1] and group['groupType'] & key:
                    form.group_flags.data += key

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Save changes",
                               parent=url_for('group_overview',
                                              groupname=groupname))

    @app.route('/group/<groupname>/+add-members', methods=['GET', 'POST'])
    @ldap_auth("Domain Admins")
    def group_addmembers(groupname):
        title = "Add members"

        if not ldap_group_exists(groupname):
            abort(404)

        form = GroupAddMembers(request.form)
        form.visible_fields = [form.new_members]

        if form.validate_on_submit():
            group = ldap_get_group(groupname)
            if 'member' in group:
                entries = set(group['member'])
            else:
                entries = set()

            for line in form.new_members.data.split("\n"):
                entry = ldap_get_entry_simple({'sAMAccountName': line.strip()})
                if not entry:
                    error = "Invalid username: %s" % line
                    flash(error, "error")
                    break

                entries.add(entry['distinguishedName'])
            else:
                try:
                    ldap_update_attribute(group['distinguishedName'],
                                          "member", list(entries))
                    flash("Members added.", "success")
                    return redirect(url_for('group_overview',
                                            groupname=groupname))
                except ldap.LDAPError as e:
                    error = e.message['info'].split(":", 2)[-1].strip()
                    error = str(error[0].upper() + error[1:])
                    flash(error, "error")
        elif form.errors:
            flash("Some fields failed validation.", "error")

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Add members",
                               parent=url_for('group_overview',
                                              groupname=groupname))

    @app.route('/group/<groupname>/+del-member/<member>',
               methods=['GET', 'POST'])
    @ldap_auth("Domain Admins")
    def group_delmember(groupname, member):
        title = "Remove group member"

        group = ldap_get_group(groupname)
        if not group or 'member' not in group:
            abort(404)

        member = ldap_get_entry_simple({'sAMAccountName': member})
        if not member:
            abort(404)

        if not member['distinguishedName'] in group['member']:
            abort(404)

        form = FlaskForm(request.form)

        if form.validate_on_submit():
            try:
                members = group['member']
                members.remove(member['distinguishedName'])
                ldap_update_attribute(group['distinguishedName'],
                                      "member", members)
                flash("Member removed.", "success")
                return redirect(url_for('group_overview', groupname=groupname))
            except ldap.LDAPError as e:
                error = e.message['info'].split(":", 2)[-1].strip()
                error = str(error[0].upper() + error[1:])
                flash(error, "error")
        elif form.errors:
                flash("Some fields failed validation.", "error")

        return render_template("pages/group_delmember.html", title=title,
                               action="Remove group member", form=form,
                               member=member['sAMAccountName'],
                               group=group['sAMAccountName'],
                               parent=url_for('group_overview',
                                              groupname=groupname))
