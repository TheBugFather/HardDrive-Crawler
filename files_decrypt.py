import os
import re
import sys
from cryptography.fernet import Fernet

if __name__ == '__main__':
    path = os.getcwd()
    re_files = re.compile(r'^e_.{1,255}\.[a-z]{2,4}$')
    key = b'UR58Mz1VHiGJa1_W42E4G0FD__Ihb4vevs3wmWhVtOc='

    for _, _, file_names in os.walk(path):
        for file in file_names:
            if re_files.match(file):
                try:
                    with open(f'{path}/{file}', 'rb') as encrypted_text:
                        data = encrypted_text.read()

                    decrypted = Fernet(key).decrypt(data)

                    with open(f'{path}/{file[2:]}', 'wb') as decrypted_text:
                        decrypted_text.write(decrypted)

                    os.remove(f'{path}/{file}')

                except (UnicodeError, OSError, IOError) as err:
                    print(f'Error occurred decrypting {file}: {err}', file=sys.stderr)

