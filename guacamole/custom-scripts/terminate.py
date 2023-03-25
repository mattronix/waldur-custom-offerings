import os
import json

import pymysql
from waldur_client import WaldurClient


def delete_desktop(instance, client):
    client.stop_instance(instance, wait=True)
    client.delete_instance_via_marketplace(instance)
    return True


def delete_from_guacamole_db(instance_uuid, cursor):
    cursor.execute("SELECT connection_id FROM guacamole_connection WHERE backend_id='{}'".format(instance_uuid))
    if cursor.fetchone() is None:
        print("ERROR: Cannot find this connection in gaucamole")
        return None

    cursor.execute("DELETE FROM guacamole_connection WHERE backend_id='{}'".format(instance_uuid))


def main():
    waldur_backend = WaldurClient(os.environ.get('BACKEND_WALDUR_URL'), os.environ.get('BACKEND_WALDUR_TOKEN'))

    db = pymysql.connect(host=os.environ.get('MYSQL_HOSTNAME'),
                         user=os.environ.get('MYSQL_USER'),
                         password=os.environ.get('MYSQL_PASSWORD'),
                         db=os.environ.get('MYSQL_DATABASE'), autocommit=True)
    cursor = db.cursor(pymysql.cursors.DictCursor)
    print("Connected to Guacamole MySQL at {}".format(os.environ.get('MYSQL_HOSTNAME')))

    delete_desktop(os.environ.get('RESOURCE_BACKEND_ID'), waldur_backend)
    print("Deleted instance with uuid {}".format(os.environ.get('RESOURCE_BACKEND_ID')))

    delete_from_guacamole_db(os.environ.get('RESOURCE_BACKEND_ID'), cursor)
    print("Deleted guacamole record for the instance")


if __name__ == "__main__":
    main()
