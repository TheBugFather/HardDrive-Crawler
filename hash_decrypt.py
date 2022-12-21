""" Built-in modules """
import sys
from pathlib import Path
# External modules #q
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

    :return:  Nothing
    """
    # Get the current working directory #
    cwd = Path('.')
    path = cwd / 'DecryptDock'

    # If the DecryptDock does not exist #
    if not path.exists():
        print_err('DecryptDock missing, now created so move files in it and rerun program')
        path.mkdir(parents=True)
        sys.exit(1)

    hash_key = b'AP92lIGyU8Zqnc568KT5ugjInAo28qwBuB5fzWYQfz0='
    crypt_sha_path = path / 'e_sha_hashes.txt'
    plain_sha_path = path / 'sha_hashes.txt'

    try:
        # Read the cipher text hashes #
        with crypt_sha_path.open('rb') as encrypted_text:
            data = encrypted_text.read()

        # Decrypt the cipher text #
        decrypted = Fernet(hash_key).decrypt(data)

        # Write the decrypted plain text to fresh file #
        with plain_sha_path.open('wb') as decrypted_text:
            decrypted_text.write(decrypted)

    # If error occurs during file operation #
    except (UnicodeError, IOError, OSError) as io_err:
        print_err(f'Error occurred decrypting hashes: {io_err}')

    # Delete the original cipher text file #
    crypt_sha_path.unlink()

    sys.exit(0)


if __name__ == '__main__':
    main()
