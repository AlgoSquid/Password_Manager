from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import click, json, os, base64


@click.group()
def cli():
    """
    Commandline password manager in a single python file
    """
    pass


@cli.command()
def create_store():
    """
    Create password store
    """
    store_name = click.prompt("Enter password store name with extension")

    # Check if it exists and ask if overide or abort
    if os.path.exists(store_name):
        click.confirm("The file already exists, override?", abort=True)

    # Ask for master password
    pwd = click.prompt("Enter master password", hide_input=True, confirmation_prompt=True)

    # Create empty store, salt for encryption and encryption scheme
    json_data = json.dumps({}).encode('utf-8')
    salt = os.urandom(16)
    fernet = _create_fernet(salt, pwd)

    # Encrypt data and test word
    encrypted_data = fernet.encrypt(json_data)
    test_word = fernet.encrypt(b'test')

    # Save bytes to file
    with open(store_name, mode='wb') as out_file:
        out_file.writelines((salt, test_word, encrypted_data))

    click.echo(f"Succesfully created password store: {store_name}")


@cli.command(short_help="Login into password store given store path")
@click.argument('filepath', type=click.Path(exists=True))
@click.password_option()
def login(filepath, password):
    """
    Login to password store given store path and password
    """
    with open(filepath, mode='rb') as file:
        salt = file.read(16)
        test_word = file.read(100)
        encrypted_data = file.read()

        # Check password
        fernet = _create_fernet(salt, password)
        try:
            if fernet.decrypt(test_word) != b'test':
                raise Exception("Incorrect password")
        except Exception as identifier:
            click.echo("Incorrect password!")
            return

    # Decrypt data and start the application
    data = fernet.decrypt(encrypted_data)
    start_shell(data, salt, fernet)


def start_shell(data, salt, fernet):
    pass


def delete_entry():
    """
    Delete user(name)/password entry
    """
    click.confirm("Are you sure you wish to delete this entry?", abort=True)


def _create_fernet(salt, password):
    """
    Creates a Fernet object for symmetric encryption. Input is salt as bytes
    and password as str. Uses the Scrypt key deviation function to create a key
    for the fernet encryption. RFC 7914 and Scrypt recommends r=8 and p=1 with n >= 2**14.
    """
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend()) 
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return Fernet(key)


if __name__ == "__main__":
    cli()


# Plan for development:
# CLI: 

# Create command: Create password store given name, prompt for master pasword twice.
# Login command: Open password store, prompt for master password and leads to the following commands:


# Store command: Store a user(name)/password pair, two input steps with verification
# Delete command: Input user(name) and delete entry in store, use confirmation
# List command: List all user(names) in the manager
# Print command: Input user(name) and retrieve password in stdout
# Change master password command: Change the masster password. Double prompt for the new password twice.