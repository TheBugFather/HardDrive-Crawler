""" Built-in modules """
import os
import re
import sys
from pathlib import Path
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
    cwd = Path('.')
    path = cwd / 'DecryptDock'

    # If the DecryptDock does not exist #
    if not path.exists():
        print_err('DecryptDock missing, now created so move files in it and rerun program')
        # Ensure storage path for exfiltration data exists #
        path.mkdir(parents=True)
        sys.exit(1)

    re_files = re.compile(r'^e_.{1,253}\.[a-z]{2,4}$')
    key = b'UR58Mz1VHiGJa1_W42E4G0FD__Ihb4vevs3wmWhVtOc='

    for file in os.scandir(str(path.resolve())):
        # If the item matches file regex and is not .keep file or decrypted hash file #
        if re_files.match(file.name) and file.name not in ('.keep', 'SHA_Hashes.txt'):
            crypt_path = path / file.name
            plain_path = path / file.name[2:]
            try:
                # Read the encrypted cipher text #
                with crypt_path.open('rb') as encrypted_text:
                    data = encrypted_text.read()

                # Decrypt the cipher text data #
                decrypted = Fernet(key).decrypt(data)

                # Write the plain text data to fresh file #
                with plain_path.open('wb') as decrypted_text:
                    decrypted_text.write(decrypted)

                # Delete the cipher text file #
                crypt_path.unlink()

            # If error occurs during file operation #
            except (UnicodeError, OSError, IOError) as io_err:
                print_err(f'Error occurred decrypting {file.name}: {io_err}')

    sys.exit(0)


if __name__ == '__main__':
    main()
