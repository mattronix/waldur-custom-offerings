import os
import json
import re

import pymysql
from waldur_client import WaldurClient


def create_desktop(hostname, client):
    instance = client.create_instance_via_marketplace(
        name=hostname,
        offering=os.environ.get("BACKEND_WALDUR_OFFERING"),
        project=os.environ.get("BACKEND_WALDUR_PROJECT"),
        image=os.environ.get("BACKEND_WALDUR_IMAGE"),
        system_volume_size=10,
        flavor=os.environ.get("BACKEND_WALDUR_FLAVOR"),
        ssh_key = os.environ.get('BACKEND_WALDUR_SSHKEY'),  # enable if required to inject a management key into VM
        security_groups=[os.environ.get("BACKEND_WALDUR_SECURITY_GROUP"), "default"],
        networks=[
            {"subnet": os.environ.get("BACKEND_WALDUR_SUBNET"), "floating_ip": ""}
        ],
    )

    return instance


def insert_to_guacamole_db(instance_uuid, name, email, ip, cursor):
    cursor.execute(
        "SELECT connection_id FROM guacamole_connection WHERE backend_id='{}'".format(
            instance_uuid
        )
    )
    if cursor.fetchone() is not None:
        print(f"ERROR: Connection id {instance_uuid} already exists.")
        return None

    cursor.execute(
        "INSERT INTO guacamole_connection (connection_name, protocol, backend_id) VALUES ('{}', 'rdp', '{}')".format(
            name, instance_uuid
        )
    )

    connection_id = cursor.lastrowid

    cursor.execute(
        "INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES \
		({}, 'hostname', '{}'), \
		({}, 'ignore-cert', 'true'), \
		({}, 'username', 'user'), \
		({}, 'port', 3389), \
		({}, 'password', '{}')".format(
            connection_id,
            ip,
            connection_id,
            connection_id,
            connection_id,
            connection_id,
            os.environ.get("DESKTOP_PASSWORD"),
        )
    )

    # Ignore error if email already exists
    cursor.execute(
        "INSERT IGNORE INTO guacamole_entity (name, type) VALUES ('{}', 'USER')".format(
            email
        )
    )

    # Ignore error if user already exists
    cursor.execute(
        "INSERT IGNORE INTO guacamole_user (entity_id, password_hash, password_date) VALUES \
        ((SELECT entity_id FROM guacamole_entity WHERE name='{}'), '', CURDATE())".format(
            email
        )
    )

    cursor.execute(
        "INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission) VALUES \
		((SELECT entity_id FROM guacamole_entity WHERE name='{}'), {}, 'READ')".format(
            email, connection_id
        )
    )


def main():
    waldur_backend = WaldurClient(
        os.environ.get("BACKEND_WALDUR_URL"), os.environ.get("BACKEND_WALDUR_TOKEN")
    )

    attributes = json.loads(os.environ.get("ATTRIBUTES"))
    desktop_name = re.sub('[^A-Za-z0-9]+', '', attributes["name"])

    db = pymysql.connect(
        host=os.environ.get("MYSQL_HOSTNAME"),
        user=os.environ.get("MYSQL_USER"),
        password=os.environ.get("MYSQL_PASSWORD"),
        db=os.environ.get("MYSQL_DATABASE"),
        autocommit=True,
    )
    cursor = db.cursor(pymysql.cursors.DictCursor)
    print("Connected to Guacamole MySQL at {}".format(os.environ.get("MYSQL_HOSTNAME")))

    instance_uuid = create_desktop(desktop_name, waldur_backend)
    print("Created instance with uuid {}".format(instance_uuid))

    instance = waldur_backend.get_instance_via_marketplace(
        instance_uuid, os.environ.get("BACKEND_WALDUR_PROJECT")
    )
    insert_to_guacamole_db(
        instance_uuid,
        desktop_name,
        os.environ.get("CREATOR_EMAIL"),
        instance["internal_ips"][0],
        cursor,
    )
    print("Added guacamole record for the instance")
    print(instance_uuid)


if __name__ == "__main__":
    main()
