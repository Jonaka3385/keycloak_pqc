FROM quay.io/keycloak/keycloak:latest

ENV KC_HTTP_ENABLED=true
ENV KC_HOSTNAME_STRICT=false

ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev"]
