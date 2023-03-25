#!/bin/bash

TOKEN=$(cat /opt/firezone/token)

source /opt/firezone/.env

curl -X PUT "http://localhost:13000/v0/configuration" \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer '$TOKEN \
  --data-binary @- << EOF
{
  "configuration": {
    "default_client_allowed_ips": "192.168.42.0/24",
    "allow_unprivileged_device_configuration": false,
    "disable_vpn_on_oidc_error": false,
    "local_auth_enabled": false,
    "logo": {"url": "https://keycloak.hpc.ut.ee/auth/resources/qm34k/login/HPC_login/img/ut_hpc_eng.svg"},
    "openid_connect_providers": [
      {
        "auto_create_users": false,
        "client_id": "$OIDC_CLIENT_ID",
        "client_secret": "$OIDC_CLIENT_SECRET",
        "discovery_document_uri": "$OIDC_DOCUMENT_URL",
        "id": "myaccessid",
        "label": "MyAccessID"
      }
    ]
  }
}
EOF

curl -X POST "http://localhost:13000/v0/users" \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer '$TOKEN \
  --data-binary @- << EOF
{
  "user": {
    "email": "$OIDC_EMAIL",
    "password": "test1234test",
    "password_confirmation": "test1234test",
    "role": "unprivileged"
  }
}
EOF
