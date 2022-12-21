# Hard-drive Crawler
![alt text](https://github.com/ngimb64/HardDrive-Crawler/blob/main/HarddriveCrawler.gif?raw=True)
![alt text](https://github.com/ngimb64/HardDrive-Crawler/blob/main/HarddriveCrawler.png?raw=True)

&#9745;&#65039; Bandit verified<br>
&#9745;&#65039; Synk verified<br>
&#9745;&#65039; Pylint verified 9.94/10

## Notice
> This tool may be used for legal purposes only.<br>
> Users take full responsibility for any actions performed using this tool.<br>
> The author accepts no liability for damage caused by this tool.<br>
> If these terms are not acceptable to you, then do not use this tool.

## Prereqs
This program runs on Windows 10 and Debian-based Linux, written in Python 3.8 and updated to version 3.10.6

## Purpose
This program recursively crawls through the uthe es userthe nd user populated directoriesany available subdirectories.
It uses regex to match specified file extension types; searching through the document for a regex match (email, ip address, phone). 
The program continues through a combination of hashing => encrypting => hashing encrypted data => writing hashes to a text file => encrypting hash file with separate key.
Finally, the program completes by emailing the encrypted results and deleting the locally created logs.

## Installation
- Run the setup.py script to build a virtual environment and install all external packages in the created venv.

> Examples:<br> 
>       &emsp;&emsp;- Windows:  `python setup.py venv`<br>
>       &emsp;&emsp;- Linux:  `python3 setup.py venv`

- Once virtual env is built traverse to the (Scripts-Windows or bin-Linux) directory in the environment folder just created.
- For Windows, in the venv\Scripts directory, execute `activate` or `activate.bat` script to activate the virtual environment.
- For Linux, in the venv/bin directory, execute `source activate` to activate the virtual environment.
- If for some reason issues are experienced with the setup script, the alternative is to manually create an environment, activate it, then run pip install -r packages.txt in project root.
- To exit from the virtual environment when finished, execute `deactivate`.

## How to use
- In your Google account, set up multi-factor authentication and generate an application password for gmail
- Open up the harddrive_crawler.py in text editor of choice, find email login section at beginning of send_mail, and add username and app password
- Open up shell (CMD or terminal)
- Enter directory containing program and execute in shell
- The program length greatly varies depending on the amount of contents in the crawl path (could be ten minutes or a few hours), check your email when it is finished
- Download encrypted files and copy them into the program folder
- Run the hash decrypt program which reveals the text hash file with the hashes for encrypted and unencrypted data
- Optional - use hash generator to confirm sha256 encrypted file hashes retained integrity
- Run file decrypt program to decrypt all the other files
- Optional - use hash generator to confirm sha256 plain text file hashes retained integrity

## Function Layout
-- harddrive_crawler.py --
> create_attachment &nbsp;-&nbsp; Creates attachment instance, populates it, and returns it to 
> send_main() function.

> smtp_handler &nbsp;-&nbsp; Facilitates sending the email to Gmail through SMTP protocol.

> create_email &nbsp;-&nbsp; Creates email instance and formats the header and body. This sets the 
> email to send to itself, since the goal is to log in and yourself email with the attached data.

> send_email &nbsp;-&nbsp; Facilitates exfiltrating encrypted loot data via Gmail.

> crypto_hash &nbsp;-&nbsp; Encrypts the hashes file.

> crypto_data &nbsp;-&nbsp; Hashes the plain text data, encrypts the data, then hashes the encrypted 
> data.

> match_logger &nbsp;-&nbsp; Iterates through file line by line, attempting to find regex matches to
> log to the log file.

> size_check &nbsp;-&nbsp; Checks the size of the passed in log name. If it is greater than or equal 
> to 20 MB, increment the log number and reset the log name with the log number. So log_name1 would 
> become log_name2.

> CompiledRegex &nbsp;-&nbsp; Class to group various compiled regex statements.

> print_err &nbsp;-&nbsp; Prints error message through stderr.

> main &nbsp;-&nbsp; Recursively crawls through user directories, searching through files for regex 
> matches to log to a text file to encrypt and exfiltrate via email.

-- hash_decrypt.py --
> print_err &nbsp;-&nbsp; Displays the passed in error message via stderr.

> main &nbsp;-&nbsp; Decrypts the encrypted exfiltration data.

-- files_decrypt.py --
> print_err &nbsp;-&nbsp; Displays the passed in error message via stderr.

> main &nbsp;-&nbsp; Decrypts the encrypted exfiltration data.