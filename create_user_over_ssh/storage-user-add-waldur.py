import paramiko
from io import StringIO
import json 
import os
import sys

def ssh_command_with_key_contents(hostname, port, username, key_contents, passphrase, check_user_command, commands):
    try:
        # Load private key from string
        key_file_obj = StringIO(key_contents)
        if passphrase:
            private_key = paramiko.RSAKey(file_obj=key_file_obj, password=passphrase)
        else:
            private_key = paramiko.RSAKey(file_obj=key_file_obj)

        # Initialize SSH client
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, port, username, pkey=private_key)

        # Check if user already exists
        stdin, stdout, stderr = client.exec_command(check_user_command, get_pty=True)
        if stdout.channel.recv_exit_status() == 0:
            print(f"cannot create user {new_user} as they exist already. Exiting ")
            sys.exit(1)

        # If user does not exist, execute the commands
        for command in commands:
            stdin, stdout, stderr = client.exec_command(command, get_pty=True)
            print(stdout.read().decode())

    except Exception as e:
        print(f"Connection failed: {str(e)}")
    finally:
        key_file_obj.close()
        client.close()
        sys.exit()

if __name__ == "__main__":

    attributes = json.loads(os.environ.get("ATTRIBUTES"))
    
    # Server and login details
    hostname = 'fs.ti'
    port = 22
    username = 'root'
    private_key_contents = '''-----BEGIN OPENSSH PRIVATE KEY-----
    -----END OPENSSH PRIVATE KEY-----'''
    private_key_passphrase = None

    # New user details
    new_user = attributes["name"]
    samba_password = attributes['password']
    new_user_password = attributes['password']

    # Command to check if user exists
    check_user_command = f'id {new_user}'

    # Commands to execute if user does not exist
    commands = [
        f"useradd -m -s /bin/bash {new_user}",
        f"echo '{new_user}:{new_user_password}' | chpasswd",
        f"(echo '{samba_password}'; echo '{samba_password}') | smbpasswd -a {new_user} -s",
        f"smbpasswd -e {new_user}",
        f"chmod 700 /home/{new_user}",
        f"chown {new_user}:{new_user} /home/{new_user}"
    ]  

    ssh_command_with_key_contents(hostname, port, username, private_key_contents, private_key_passphrase, check_user_command, commands)
