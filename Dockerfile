FROM python:alpine

ARG UID=2541

ENV LDAP_DOMAIN=""
ENV LDAP_SERVER=""
ENV LDAP_DN=""
ENV URL_PREFIX=""

COPY . /usr/share/samba4-manager/
RUN adduser --home /usr/share/samba4-manager/ \
            --disabled-password \
            --no-create-home \
            --uid ${UID} \
            abc \
 && cd /usr/share/samba4-manager/ \
 && chown -R abc:root . \
 && chmod -R o-rwx . \
 && chmod -R -w . \
 && chown root:root docker-entrypoint.sh \
 && chmod 0500 docker-entrypoint.sh \
 && apk --no-cache add openldap-clients \
 && apk --no-cache --virtual .build-deps add \
    gcc \
    musl-dev \
    openldap-dev \
 && pip install --no-cache-dir -r requirements.txt \
 && apk del .build-deps

VOLUME /etc/samba4-manager
EXPOSE 8080
ENTRYPOINT [ "/usr/share/samba4-manager/docker-entrypoint.sh" ]
