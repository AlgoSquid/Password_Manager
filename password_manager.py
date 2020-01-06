from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import click, json, os, base64, cmd, getpass


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
    empty_store = {}
    salt = os.urandom(16)
    fernet = _create_fernet(salt, pwd)

    # Encrypt and save to file
    _save_password_store(empty_store, store_name, salt, fernet)
    click.echo(f"Succesfully created password store: {store_name}")


@cli.command(short_help="Login into password store given store path")
@click.argument('filepath', type=click.Path(exists=True))
@click.password_option(confirmation_prompt=False)
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

    # Decrypt data and start the shell
    data = fernet.decrypt(encrypted_data)
    PasswordStoreShell(data, filepath, salt, fernet).cmdloop()


def _create_fernet(salt, password):
    """
    Creates a Fernet object for symmetric encryption. Input is salt as bytes
    and password as str. Uses the Scrypt key deviation function to create a key
    for the fernet encryption. RFC 7914 and Scrypt recommends r=8 and p=1 with n >= 2**14.
    """
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend()) 
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return Fernet(key)


def _save_password_store(data_store, filepath, salt, fernet):
    """
    Saves password store encrypted on disk. Input is password store as json, 
    the file path to write the encrypted file to, salt as bytes and a fernet
    object for symmetric encryption. The result is a file on the form:
    [salt 16 bytes][the word test encrypted 100 bytes][data store encrypted remaining bytes]
    """
    encoded_data_Store = json.dumps(data_store).encode('utf-8')
    encrypted_data = fernet.encrypt(encoded_data_Store)
    test_word = fernet.encrypt(b'test')
    with open(filepath, mode='wb') as out_file:
        out_file.writelines((salt, test_word, encrypted_data))


class PasswordStoreShell(cmd.Cmd):
    intro = 'Welcome to the password store shell (pss).   Type help or ? to list commands.\n'
    prompt = '(pss) '

    def __init__(self, data_store, filepath, salt, fernet):
        super().__init__()
        self.data_store = json.loads(data_store.decode('utf-8'))
        self.filepath = filepath
        self.salt = salt
        self.fernet = fernet

    def do_store(self, arg):
        """
        Store password by specifying identifier and afterwards password:  store identifier 
        """
        # Do not handle empty strings
        if arg is None or arg == "":
            return

        # Ensure we do not override by mistake
        if arg in self.data_store:
            answer = None
            while answer not in ('y', 'N'):
                answer = input(f"{arg} already exist as identifier in the store, override? [y/N]")
                if answer == 'y':
                    break
                elif answer == 'N':
                    print("Aborted!")
                    return
                else:
                    print("Invalid answer, try again!")

        # Get password and store identifier and password
        while True:
            password = getpass.getpass(f"password for {arg}:")
            if password is None or password == "":
                print("*** Error: The password cannot be empty")
            else:
                break
        
        self.data_store[arg] = password
        print(f"{arg} was successfully stored")

    def do_delete(self, arg):
        """
        Delete password by specifying identifier:  delete identifier 
        """
        # Do not handle empty strings
        if arg is None or arg == "":
            return
        
        # Ensure we do not override by mistake
        if arg in self.data_store:
            answer = None
            while answer not in ('y', 'N'):
                answer = input(f"Are you certain you wish to delete {arg}? [y/N]")
                if answer == 'y':
                    self.data_store.pop(arg)
                    print(f"{arg} was successfully deleted")
                    return
                elif answer == 'N':
                    print("Aborted!")
                    return
                else:
                    print("Invalid answer, try again!")
        else:
            print(f"*** Error: {arg} is not in password store")

    def do_list(self, arg):
        """
        List all passoword idenfiers alphabetically:  list
        """
        for identifier in sorted(self.data_store.keys()): 
            print(identifier) 

    def do_retrieve(self, arg):
        """
        Retrieve password by specifiying identifier:  retrieve identifier 
        """
        # Do not handle empty strings
        if arg is None or arg == "":
            return

        if arg in self.data_store:
            print(f"{arg}: '{self.data_store[arg]}'")
        else:
            print(f"*** Error: {arg} is not in password store")

    def do_change_master_password(self, arg):
        """
        Change master password by specifying new password in prompt:  change_master_password
        """
        while True:
            new_psw_1 = getpass.getpass("Enter new master password:")
            new_psw_2 = getpass.getpass("Repeat for confirmation:")
            if new_psw_1 is None or new_psw_1 == "":
                print("*** Error: The password cannot be empty")
            elif new_psw_1 == new_psw_2:
                break
            else:
                print("*** Error: The two entered values do not match")

        self.salt = os.urandom(16)
        self.fernet = _create_fernet(self.salt, new_psw_1)
        print("Successfully changed master password")

    def do_exit(self, arg):
        """
        Stop the password store shell and save the password store:  exit
        """
        return True

    def postcmd(self, stop, line):
        """
        Hook method executed after a command has finished being executed.
        Saves the current password store with the current fernet and salt.
        """
        _save_password_store(self.data_store, self.filepath, self.salt, self.fernet)
        return stop


if __name__ == "__main__":
    cli()