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

from flask import url_for
from werkzeug.urls import uri_to_iri


class ReverseProxied(object):
    def __init__(self, app, prefix):
        self.app = app
        if prefix[0] != "/":
            self.prefix = "/%s" % prefix
        else:
            self.prefix = prefix

    def __call__(self, environ, start_response):
        script_name = self.prefix
        environ['SCRIPT_NAME'] = script_name
        path_info = environ['PATH_INFO']
        if path_info.startswith(script_name):
            environ['PATH_INFO'] = path_info[len(script_name):]

        return self.app(environ, start_response)


def iri_for(endpoint, **values):
    """
        Wrapper to url_for for utf-8 URLs.
    """
    return uri_to_iri(url_for(endpoint, **values))
