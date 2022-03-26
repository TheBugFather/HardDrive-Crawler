# Hard-drive Crawler
![alt text](https://github.com/ngimb64/HardDrive-Crawler/blob/main/HardDriveCrawler.png?raw=True)

## Prereqs
> This program runs on Windows, written in Python 3.8

## Installation
> Run the setup.py script to install external modules.

## Purpose
> This program recursively crawls through the specified directory and any available subdirectories.
> It uses regex to match specified file extension types; proceeding to search through the 
> document for a regex match (email, ip address, phone). The program continues through a combination
> of hashing => encrypting => hashing encrypted data => writing hashes to a text file =>
> encrypting hash file with separate key. Finally, the program completes by emailing the
> encrypted results and deleting the locally created logs.

## How to use
- Confirm your email account allows less secure apps (otherwise api call are inhibited)
- Open up the harddriveCrawler.py in text editor of choice, find email section, and add username & password
- Open up Command Prompt (CMD)
- Enter directory containing program and execute in shell
- The program will run for about 45 seconds, check your email when it is finished
- Download encrypted files and copy them into the directory with the program and decrypt files
- Run the hash decrypt program which reveals the text hash file with the hashes for encrypted & unencrypted data
- Optional - use hash generator to confirm sha256 encrypted file hashes retained entegrity
- Run file decrypt program to decrypt all the other files
- Optional - use hash generator to confirm sha256 plain text file hashes retained entegrity