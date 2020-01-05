### Introduction
This a single-file password manager that keeps all your passwords safe in
a single encrypted binary file. It uses python 3 and the two packages
click and cryptography, see requirements.txt. 


### How To use
A password store has to be created as the first step, where you will
be prompted to give a file name and extension and to supply a master password:

```
python password_manager.py create_store
```

It is now possible to login into the password store and manage your passwords:

```
python password_manager.py login <your_password_store_filename>
```


From here you enter a shell where it is possible to store, delete, retrieve
and list passwords and their identifiers (usernames). It is also possible to
change the master password. Enter help or ? to see usable commands.


The password store is saved everytime a command is dispatched and completed
succesfully without errors, this includes when the exit command or master 
password change is issued.