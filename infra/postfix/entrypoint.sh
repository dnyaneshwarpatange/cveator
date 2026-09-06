#!/bin/sh
set -eu

: "${MAIL_DOMAIN:?MAIL_DOMAIN must be set}"
: "${MAIL_HOSTNAME:?MAIL_HOSTNAME must be set}"
: "${DKIM_SELECTOR:?DKIM_SELECTOR must be set}"

source_key="/run/dkim/${DKIM_SELECTOR}.private"
installed_key="/etc/opendkim/keys/${MAIL_DOMAIN}/${DKIM_SELECTOR}.private"

if [ ! -f "${source_key}" ]; then
  echo "Missing DKIM private key: ${source_key}" >&2
  exit 1
fi

mkdir -p "/etc/opendkim/keys/${MAIL_DOMAIN}" /run/opendkim
cp "${source_key}" "${installed_key}"
chown opendkim:opendkim "${installed_key}"
chmod 0600 "${installed_key}"
chown opendkim:opendkim /run/opendkim

cat > /etc/opendkim/opendkim.conf <<EOF
Syslog                  yes
SyslogSuccess           yes
Canonicalization        relaxed/simple
Mode                    s
OversignHeaders         From
Socket                  inet:8891@127.0.0.1
UserID                  opendkim
UMask                   007
PidFile                 /run/opendkim/opendkim.pid
Domain                  ${MAIL_DOMAIN}
Selector                ${DKIM_SELECTOR}
KeyFile                 ${installed_key}
InternalHosts           refile:/etc/opendkim/TrustedHosts
EOF

cat > /etc/opendkim/TrustedHosts <<EOF
127.0.0.1
localhost
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
EOF

postconf -e "myhostname = ${MAIL_HOSTNAME}"
postconf -e "mydomain = ${MAIL_DOMAIN}"
postconf -e 'myorigin = $mydomain'
postconf -e 'inet_interfaces = all'
postconf -e 'inet_protocols = all'
postconf -e 'mydestination ='
postconf -e 'relay_domains ='
postconf -e 'mynetworks = 127.0.0.0/8 [::1]/128 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16'
postconf -e 'smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination'
postconf -e 'smtpd_recipient_restrictions = permit_mynetworks, reject'
postconf -e 'smtp_tls_security_level = may'
postconf -e 'smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt'
postconf -e 'milter_default_action = tempfail'
postconf -e 'milter_protocol = 6'
postconf -e 'smtpd_milters = inet:127.0.0.1:8891'
postconf -e 'non_smtpd_milters = inet:127.0.0.1:8891'
postconf -e 'maillog_file = /dev/stdout'

opendkim -x /etc/opendkim/opendkim.conf
exec postfix start-fg
