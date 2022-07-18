# Built-in modules #
import os
import sys

# External modules #q
from cryptography.fernet import Fernet

if __name__ == '__main__':
    path = os.getcwd()
    hash_key = b'AP92lIGyU8Zqnc568KT5ugjInAo28qwBuB5fzWYQfz0='

    try:
        with open(f'{path}/e_SHA_Hashes.txt', 'rb') as encrypted_text:
            data = encrypted_text.read()

        decrypted = Fernet(hash_key).decrypt(data)

        with open(f'{path}/SHA_Hashes.txt', 'wb') as decrypted_text:
            decrypted_text.write(decrypted)

    except (UnicodeError, IOError, OSError) as err:
        print('Error occurred decrypting hashes', file=sys.stderr)

    os.remove(f'{path}/e_SHA_Hashes.txt')
