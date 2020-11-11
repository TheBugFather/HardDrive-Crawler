## Prereqs
> To make sure this program runs as designed Python 3.8 
> should be installed. This project has many modules incorporated,
> some of which are not included by default. Any missing modules
> have to be installed with PIP before the program can run. I recommend
> simply enter the module name in search engine and finding the documentation. The 
> PIP command for installation is usually one of the first things mentioned.
> Also with Python it is common to have multiple modules with a similar names.
> So if errors are being raised about not having a certain module it is
> most likely the wrong module with a similar name to the one that is required
> was installed instead of the required module.

## Installation
> Enter Python downloads in a search engine and obtain version 3.8 from the official website. 
> Run the installer and follow the default installation procedures. 
> Also search for any required modules and install them with PIP in Command Prompt.

## Purpose
> This program recursivly crawls through the specified directory and any available subdirectories.
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