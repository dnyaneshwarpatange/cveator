FROM alpine:3.21

RUN apk add --no-cache ca-certificates opendkim opendkim-utils postfix tini

COPY entrypoint.sh /usr/local/bin/postfix-entrypoint
RUN chmod 0755 /usr/local/bin/postfix-entrypoint

EXPOSE 25
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/postfix-entrypoint"]
