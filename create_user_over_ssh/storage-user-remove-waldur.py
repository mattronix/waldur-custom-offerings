import paramiko
from io import StringIO
import json 
import os

def escape_password_for_bash(password):
    """
    Escapes special characters in the password for safe use in Bash.

    Args:
    password (str): The password to escape.

    Returns:
    str: The escaped password.
    """
    # List of characters to escape
    # Adding backslash (\) to the list of characters to be escaped
    special_chars = ['\\', '`', '$', '"', '!', '^']
    
    # Escape each special character with a backslash
    escaped_password = ''.join(['\\' + char if char in special_chars else char for char in password])
    return escaped_password


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
        if not stdout.channel.recv_exit_status() == 0:
            print(f"User {new_user} does not exists. Exiting.")
            return

        # If user does not exist, execute the commands
        for command in commands:
            stdin, stdout, stderr = client.exec_command(command, get_pty=True)
            print(stdout.read().decode())

    except Exception as e:
        print(f"Connection failed: {str(e)}")
    finally:
        key_file_obj.close()
        client.close()

if __name__ == "__main__":

    attributes = json.loads(os.environ.get("RESOURCE_ATTRIBUTES"))


    
    # Server and login details
    hostname = 'fs.ti'
    port = 22
    username = 'root'
    private_key_contents = '''-----BEGIN OPENSSH PRIVATE KEY-----
    -----END OPENSSH PRIVATE KEY-----'''
    private_key_passphrase = None
    
    # New user details
    new_user = attributes["name"]
    new_user_password = escape_password_for_bash(attributes["password"])
    samba_password = escape_password_for_bash(attributes['password'])

    # Command to check if user exists
    check_user_command = f'id {new_user}'

    # Commands to execute if user does not exist
    commands = [
        f'userdel -r {new_user}',
    ]  

    ssh_command_with_key_contents(hostname, port, username, private_key_contents, private_key_passphrase, check_user_command, commands)
