#!/bin/sh
APP_CONFIG="${APP_CONFIG:-/etc/samba4-manager/manager.cfg}"
APP_DATA="/usr/share/samba4-manager/"

if [[ ! -f "$APP_CONFIG" ]] ; then
    cp "${APP_DATA}/manager.cfg.example" "$APP_CONFIG"
    chown abc:root "$APP_CONFIG"
    chmod o-rwx "$APP_CONFIG"

    secret="$(LC_ALL=C tr -dc 'A-Za-z0-9!#$%&()*+,-.:;<=>?@[\]^_`{|}~' </dev/urandom | head -c 32)"
    sed -i s/INSERT-SECRET-KEY-HERE/$secret/g "$APP_CONFIG"

    [[ -z $LDAP_DOMAIN ]] && LDAP_DOMAIN="$(dnsdomainname)"
fi

if [[ ! -z $LDAP_DOMAIN ]] ; then
    sed -i -E "s/#?(LDAP_DOMAIN = \")[^\"]*(\")/\1${LDAP_DOMAIN}\2/g" "$APP_CONFIG"
fi
if [[ ! -z $LDAP_SERVER ]] ; then
    sed -i -E "s/#?(LDAP_SERVER = \")[^\"]*(\")/\1${LDAP_SERVER}\2/g" "$APP_CONFIG"
fi
if [[ ! -z $LDAP_DN ]] ; then
    sed -i -E "s/#?(LDAP_DN = \")[^\"]*(\")/\1${LDAP_DN}\2/g" "$APP_CONFIG"
fi
if [[ ! -z $URL_PREFIX ]] ; then
    sed -i -E "s/#?(URL_PREFIX = \")[^\"]*(\")/\1${URL_PREFIX}\2/g" "$APP_CONFIG"
fi

exec su - abc -c "APP_CONFIG='${APP_CONFIG}' APP_DATA='${APP_DATA}' ./samba4-manager"
