#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name='samba4-manager',
    version='0.1',
    description='Web interface to manage samba4',
    author='Stéphane Graber',
    author_email='stgraber@stgraber.org',
    url='https://github.com/stgraber/samba4-manager',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    scripts=["samba4-manager"],
    install_requires=[
      "dnspython",
      "flask",
      "flask_wtf",
      "python-ldap",
    ])
