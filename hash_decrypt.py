# Built-in modules #
import os
import pathlib
import sys

# External modules #q
from cryptography.fernet import Fernet


"""
########################################################################################################################
Name:       PrintErr
Purpose:    Displays the passed in error message via stderr.
Parameters: The error message to be displayed.
Returns:    Nothing
########################################################################################################################
"""
def PrintErr(msg: str):
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)


"""
########################################################################################################################
Name:       main
Purpose:    Decrypts the encrypted exfiltration data.
Parameters: Nothing
Returns:    Nothing
########################################################################################################################
"""
def main():
    # Get the current working directory #
    cwd = os.getcwd()

    # If the OS is Windows #
    if os.name == 'nt':
        path = f'{cwd}\\DecryptDock\\'
    # If the OS is Linux #
    else:
        path = f'{cwd}/DecryptDock/'

    # Ensure storage path for exfiltration data exists #
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)

    # If the DecryptDock does not exist #
    if not os.path.isdir(path):
        PrintErr('DecryptDock missing, now created so move files in it and rerun program')
        os.mkdir(path)
        sys.exit(1)

    hash_key = b'AP92lIGyU8Zqnc568KT5ugjInAo28qwBuB5fzWYQfz0='

    try:
        # Read the cipher text hashes #
        with open(f'{path}e_SHA_Hashes.txt', 'rb') as encrypted_text:
            data = encrypted_text.read()

        # Decrypt the cipher text #
        decrypted = Fernet(hash_key).decrypt(data)

        # Write the decrypted plain text to fresh file #
        with open(f'{path}SHA_Hashes.txt', 'wb') as decrypted_text:
            decrypted_text.write(decrypted)

    # If error occurs during file operation #
    except (UnicodeError, IOError, OSError) as io_err:
        PrintErr(f'Error occurred decrypting hashes: {io_err}')

    # Delete the original cipher text file #
    os.remove(f'{path}e_SHA_Hashes.txt')


if __name__ == '__main__':
    try:
        main()

    # If unknown exception occurs #
    except Exception as err:
        PrintErr(f'Unknown error occurred: {err}')
