""" Built-in modules """
import os
import pathlib
import re
import sys

# External modules #
from cryptography.fernet import Fernet


def print_err(msg: str):
    """
    Displays the passed in error message via stderr.

    :param msg:  The error message to be displayed.
    :return:  Nothing
    """
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)


def main():
    """
    Decrypts the encrypted exfiltration data.

    :return: Nothing
    """
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
        print_err('DecryptDock missing, now created so move files in it and rerun program')
        os.mkdir(path)
        sys.exit(1)

    re_files = re.compile(r'^e_.{1,253}\.[a-z]{2,4}$')
    key = b'UR58Mz1VHiGJa1_W42E4G0FD__Ihb4vevs3wmWhVtOc='

    for file in os.scandir(path):
        # If the item matches file regex and is not .keep file or decrypted hash file #
        if re_files.match(file.name) and file.name not in ('.keep', 'SHA_Hashes.txt'):
            try:
                # Read the encrypted cipher text #
                with open(f'{path}{file.name}', 'rb') as encrypted_text:
                    data = encrypted_text.read()

                # Decrypt the cipher text data #
                decrypted = Fernet(key).decrypt(data)

                # Write the plain text data to fresh file #
                with open(f'{path}{file.name[2:]}', 'wb') as decrypted_text:
                    decrypted_text.write(decrypted)

                # Delete the cipher text file #
                os.remove(f'{path}{file.name}')

            # If error occurs during file operation #
            except (UnicodeError, OSError, IOError) as io_err:
                print_err(f'Error occurred decrypting {file.name}: {io_err}')

    sys.exit(0)


if __name__ == '__main__':
    main()
