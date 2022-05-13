# Hard-drive Crawler
![alt text](https://github.com/ngimb64/HardDrive-Crawler/blob/main/HardDriveCrawler.png?raw=True)

## Notice
> This tool may be used for legal purposes only.  Users take full responsibility
> for any actions performed using this tool.  The author accepts no liability
> for damage caused by this tool.  If these terms are not acceptable to you, then
> do not use this tool.

## Prereqs
> This program runs on Windows, written in Python 3.8

## Installation
- Run the setup.py script to build a virtual environment and install all external packages in the created venv.

> Example:<br>
> python3 setup.py "venv name"

- Once virtual env is built traverse to the Scripts directory in the environment folder just created.
- In the Scripts directory, execute the "activate" script to activate the virtual environment.

## Purpose
> This program recursively crawls through the specified directory and any available subdirectories.
> It uses regex to match specified file extension types; proceeding to search through the 
> document for a regex match (email, ip address, phone). The program continues through a combination
> of hashing => encrypting => hashing encrypted data => writing hashes to a text file =>
> encrypting hash file with separate key. Finally, the program completes by emailing the
> encrypted results and deleting the locally created logs.

## How to use
- Confirm your email account allows less secure apps (otherwise api call are inhibited)
- Open up the harddriveCrawler.py in text editor of choice, find email section, and add username and password
- Open up Command Prompt (CMD)
- Enter directory containing program and execute in shell
- The program will run for about 45 seconds, check your email when it is finished
- Download encrypted files and copy them into the directory with the program and decrypt files
- Run the hash decrypt program which reveals the text hash file with the hashes for encrypted and unencrypted data
- Optional - use hash generator to confirm sha256 encrypted file hashes retained integrity
- Run file decrypt program to decrypt all the other files
- Optional - use hash generator to confirm sha256 plain text file hashes retained integrity