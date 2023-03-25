import os
import json
import re
import uuid
from functools import cached_property

from keycloak import KeycloakAdmin
from waldur_client import WaldurClient


WALDUR_API_URL = os.environ.get('WALDUR_API_URL')
WALDUR_API_TOKEN = os.environ.get('WALDUR_API_TOKEN')

KEYCLOAK_URL = os.environ.get('KEYCLOAK_URL', 'http://localhost:8080/')
KEYCLOAK_USERNAME = os.environ.get('KEYCLOAK_USERNAME', 'admin')
KEYCLOAK_PASSWORD = os.environ.get('KEYCLOAK_PASSWORD', 'admin')
KEYCLOAK_REALM = os.environ.get('KEYCLOAK_REALM', 'master')
CREATOR_EMAIL = os.environ.get('CREATOR_EMAIL', 'support@hpc.ut.ee')

attributes = json.loads(os.environ.get("ATTRIBUTES"))
TENANT_UUID = re.findall("Tenant UUID: (.+)\.", attributes['tenant'])[0]

#print(f"DEBUG: {TENANT_UUID}")

IMAGE = os.environ.get('IMAGE', 'cirros')
FLAVOR = os.environ.get('FLAVOR', 'tempest1')
SYSTEM_VOLUME_SIZE = int(os.environ.get('SYSTEM_VOLUME_SIZE', 4))

RUN_BUTANE_IN_DOCKER = os.environ.get('RUN_BUTANE_IN_DOCKER', False)

if RUN_BUTANE_IN_DOCKER:
    BUTANE_COMMAND = "docker run --rm -i quay.io/coreos/butane:latest < vm.conf.yaml > vm.conf.json"
else:
    BUTANE_COMMAND = "butane vm.conf.yaml > vm.conf.json"


vm_config = """variant: flatcar
version: 1.0.0
systemd:
  units:
    - name: firezone.service
      enabled: true
      contents: |
        [Unit]
        Description=FireZone docker-compose service
        After=docker.service
        [Service]
        Environment=OIDC_CLIENT_ID={KEYCLOAK_CLIENT_ID}
        Environment=OIDC_CLIENT_SECRET={CLIENT_SECRET}
        Environment=OIDC_DOCUMENT_URL=https://keycloak.hpc.ut.ee/auth/realms/ETAIS/.well-known/openid-configuration
        Environment=LOGO_UUID=34b35eb7-8dee-4342-95c3-b0bae87faaa7
        Environment=LOGO_URL=https://keycloak.hpc.ut.ee/auth/resources/qm34k/login/HPC_login/img/ut_hpc_eng.svg
        Environment=EXTERNAL_URL=https://{SERVER_NAME}.cloud.ut.ee
        Environment=OIDC_EMAIL={OIDC_EMAIL}
        Environment=ADMIN_EMAIL=support@hpc.ut.ee
        TimeoutStartSec=0
        WorkingDirectory=/opt/firezone/
        ExecStartPre=bash /opt/firezone/pre.sh
        ExecStart=/opt/bin/docker-compose up
        ExecStartPost=bash /opt/firezone/post.sh
        ExecStop=/opt/bin/docker-compose down
        [Install]
        WantedBy=multi-user.target

storage:
  directories:
    - path: /opt/bin
      mode: 0755
      overwrite: false

    - path: /opt/firezone
      mode: 0755
      overwrite: true

  files:
    - path: /etc/ssh/auth_principals/root
      mode: 0600
      overwrite: true
      contents:
        inline: |
          root
          hpc
          firezone

    - path: /opt/firezone/pre.sh
      mode: 0755
      contents:
        inline: |
          #!/bin/sh

          wget -q https://github.com/docker/compose/releases/download/v2.13.0/docker-compose-linux-x86_64 -O /opt/bin/docker-compose
          chmod +x /opt/bin/docker-compose

          if [ ! -f /opt/firezone/.env ]; then
            docker run --rm --name firezone-env-provisioner firezone/firezone bin/gen-env > .env

            #sed -i 's#OIDC_CLIENT_ID#'"$OIDC_CLIENT_ID"'#g' firezone_update_db.sql
            #sed -i 's#OIDC_CLIENT_SECRET#'"$OIDC_CLIENT_SECRET"'#g' firezone_update_db.sql
            #sed -i 's#OIDC_DOCUMENT_URL#'"$OIDC_DOCUMENT_URL"'#g' firezone_update_db.sql
            #sed -i 's#LOGO_UUID#'"$LOGO_UUID"'#g' firezone_update_db.sql
            #sed -i 's#LOGO_URL#'"$LOGO_URL"'#g' firezone_update_db.sql
            sed -i -r 's#EXTERNAL_URL=_CHANGE_ME_#EXTERNAL_URL='"$EXTERNAL_URL"'#g' .env
            sed -i -r 's#ADMIN_EMAIL=_CHANGE_ME_#ADMIN_EMAIL='"$ADMIN_EMAIL"'#g' .env
            echo "WIREGUARD_IPV6_ENABLED=false" >> .env
            echo "TELEMETRY_ENABLED=false" >> .env
            #echo "DOCKER_REGISTRY_PREFIX=registry.hpc.ut.ee/mirror/" >> .env
            echo "OIDC_CLIENT_ID=$OIDC_CLIENT_ID" >> .env
            echo "OIDC_CLIENT_SECRET=$OIDC_CLIENT_SECRET" >> .env
            echo "OIDC_DOCUMENT_URL=$OIDC_DOCUMENT_URL" >> .env
            echo "OIDC_EMAIL=$OIDC_EMAIL" >> .env
          fi

    - path: /opt/firezone/post.sh
      mode: 0755
      contents:
        inline: |
            #!/bin/bash
            sleep 5
            until $(curl --output /dev/null --silent --head --fail http://localhost:13000); do
                printf '.'
                sleep 5
            done
            docker exec firezone-firezone-1 bin/create-or-reset-admin
            docker exec firezone-firezone-1 bin/create-api-token > /opt/firezone/token
            /opt/firezone/firezone_update_configuration.sh
            #/opt/bin/docker-compose restart firezone

    - path: /opt/firezone/firezone_update_configuration.sh
      mode: 0755
      contents:
        source: "https://raw.githubusercontent.com/waldur/firezone/master/firezone_update_configuration.sh"

    - path: /opt/firezone/docker-compose.yml
      mode: 0644
      contents:
        source: "https://raw.githubusercontent.com/waldur/firezone/master/firezone-docker-compose/docker-compose.yml"

    - path: /etc/ssh/hpc-ssh-public-key.pem
      mode: 0644
      overwrite: true
      contents:
        source: "https://github.com/yefimg.keys"

    - path: /etc/ssh/sshd_config
      mode: 0600
      overwrite: true
      contents:
        inline: |
          # Use most defaults for sshd configuration.
          Subsystem sftp internal-sftp
          ClientAliveInterval 180

          UseDNS no
          UsePAM yes

          PermitRootLogin without-password
          AllowUsers core root
          TrustedUserCAKeys /etc/ssh/hpc-ssh-public-key.pem
          AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u


          PrintLastLog no # handled by PAM
          PrintMotd no # handled by PAM

          Ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
          MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,umac-128-etm@openssh.com,umac-128@openssh.com
          KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256

    - path: /etc/flatcar/update.conf
      contents:
        inline: |
          REBOOT_STRATEGY=reboot
          LOCKSMITHD_REBOOT_WINDOW_START=01:00
          LOCKSMITHD_REBOOT_WINDOW_LENGTH=2h          
      mode: 0420"""


class Backend:
    def __init__(self):
        kwargs = dict(
            server_url=KEYCLOAK_URL,
            username=KEYCLOAK_USERNAME,
            password=KEYCLOAK_PASSWORD,
            realm_name=KEYCLOAK_REALM,
            verify=True
        )
        self._keycloak_client = KeycloakAdmin(**kwargs)

    @property
    def keycloak_client(self):
        self._keycloak_client.refresh_token()
        return self._keycloak_client

    @cached_property
    def waldur_client(self):
        return WaldurClient(WALDUR_API_URL, WALDUR_API_TOKEN)

    @cached_property
    def client_id(self):
        for c in self.keycloak_client.get_clients():
            if c['clientId'] == self.keycloak_new_client_id:
                return c['id']

        return self.keycloak_client.create_client({'clientId': self.keycloak_new_client_id,
            'secret': uuid.uuid4().hex, 
            'redirectUris': ['https://{}.cloud.ut.ee/*'.format(self.keycloak_new_client_id)]})

    @cached_property
    def keycloak_new_client_id(self):
        return 'vpn-' + self.filter_letters_numbers(self.waldur_tenant['name'])

    @cached_property
    def client_secret(self):
        response = self.keycloak_client.get_client_secrets(self.client_id)
        try:
            return response['value']
        except KeyError:
            raise Exception('Error get keycloak client. Response: %s' % response)

    @cached_property
    def get_or_create_client_role(self):
        name = 'role-{}'.format(self.keycloak_new_client_id)

        for r in self.keycloak_client.get_client_roles(self.client_id):
            if r['name'] == name:
                return r['name']

        return self.keycloak_client.create_client_role(
            client_role_id=self.client_id,
            payload={
                'name': name,
                'clientRole': True
            }
        )

    def generate_yaml_conf(self):
        conf = vm_config.format(
            KEYCLOAK_CLIENT_ID=self.keycloak_new_client_id,
            SERVER_NAME=self.keycloak_new_client_id,
            CLIENT_SECRET=self.client_secret,
            OIDC_EMAIL=CREATOR_EMAIL
        )

        with open('./vm.conf.yaml', mode='w') as f:
            f.write(conf)

        os.system(BUTANE_COMMAND)

    @cached_property
    def waldur_tenant(self):
        response = self.waldur_client.list_tenants({'backend_id': TENANT_UUID})
        #print(f"DEBUG: {response}")

        if not list(response):
            raise Exception('Tenant is not found.')

        if not list(response):
            raise Exception('Multiple tenants found.')

        return response[0]

    def filter_letters_numbers(self, s):
        return ''.join(c for c in s if c.isalnum())

    def get_waldur_vm_project_uuid(self):
        return self.waldur_tenant['project_uuid']

    def get_waldur_vm_offering_uuid(self):
        response = self.waldur_client.list_service_settings({'scope_uuid': self.waldur_tenant['uuid']})

        if not len(response):
            raise Exception('Service setting is not found.')

        if len(response) > 1:
            raise Exception('Multiple service settings found.')

        ss_uuid = response[0]['uuid']

        response = self.waldur_client.list_marketplace_public_offerings({
            'scope_uuid': ss_uuid,
            'type': 'OpenStackTenant.Instance'
        })

        if not len(response):
            raise Exception('Offering is not found.')

        if len(response) > 1:
            raise Exception('Multiple offerings  found.')

        return response[0]['uuid']

    @cached_property
    def waldur_subnet_name(self):
        response = self.waldur_client.list_networks({'tenant_uuid': self.waldur_tenant['uuid']})
        return response[0]['subnets'][0]['name']

    def create_security_group(self):
        existing_security_group = self.waldur_client.get_security_group(self.waldur_tenant['uuid'], "VPN-udp")

        if existing_security_group is None:
            return self.waldur_client.create_security_group(
                tenant=self.waldur_tenant['uuid'],
                name='VPN-udp',
                rules=[
                {
                    'direction': 'ingress',
                    'from_port': 51820,
                    'ethertype': 'IPv4',
                    'protocol': 'udp',
                    'to_port': 51820,
                }
                ],
            )
        else:
            return existing_security_group

    def create_vm(self):
        self.get_or_create_client_role
        self.generate_yaml_conf()
        self.create_security_group()

        with open('./vm.conf.json', mode='r') as f:
            conf = f.read()

        return self.waldur_client.create_instance_via_marketplace(
            name=self.keycloak_new_client_id,
            offering=self.get_waldur_vm_offering_uuid(),
            project=self.get_waldur_vm_project_uuid(),
            networks=[{"subnet": self.waldur_subnet_name, "floating_ip": "auto"}],
            image=IMAGE,
            system_volume_size=SYSTEM_VOLUME_SIZE,
            user_data=conf,
            security_groups=["default", "web", "ssh", "VPN-udp"],
            flavor=FLAVOR,
            ssh_key="user@laptop.yefim"
        )


if __name__ == "__main__":
    backend = Backend()
    print(backend.create_vm())
