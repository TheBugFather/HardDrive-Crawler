import os
from cryptography.fernet import Fernet

if __name__ == '__main__':
    path = os.getcwd()

    hash_key = b'AP92lIGyU8Zqnc568KT5ugjInAo28qwBuB5fzWYQfz0='
    with open(path + '/' + 'e_SHA_Hashes.txt', 'rb') as encrypted_text:
        data = encrypted_text.read()
    decrypted = Fernet(hash_key).decrypt(data)
    with open(path + '/' + 'SHA_Hashes.txt', 'ab') as decrypted_text:
        decrypted_text.write(decrypted)
    os.remove(path + '/' + 'e_SHA_Hashes.txt')