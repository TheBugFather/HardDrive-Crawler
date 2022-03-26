import os
import re
from cryptography.fernet import Fernet

if __name__ == '__main__':
    path = os.getcwd()
    re_files = re.compile(r'^e_.+\.txt$')
    key = b'UR58Mz1VHiGJa1_W42E4G0FD__Ihb4vevs3wmWhVtOc='
    
    for _, _, file_names in os.walk(path):
        for file in file_names:
            if re_files.match(file):
                with open(f'{path}/{file}', 'rb') as encrypted_text:
                    data = encrypted_text.read()

                decrypted = Fernet(key).decrypt(data)

                with open(f'{path}/{file[2:]}', 'ab') as decrypted_text:
                    decrypted_text.write(decrypted)

                os.remove(f'{path}/{file}')
