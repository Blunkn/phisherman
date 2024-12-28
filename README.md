# Phisherman
---

An email metadata extractor. Designed to determine if an email could be a phish or not.

Inspired by a program I happened upon during my service in the DIS.

If you are who I think you are, please don't OSA me. I didn't lift any code from inside.

## Features
---
- Supports Gmail & Outlook emails.
- Takes files in input folder, extracts the following:
    - Sender Name & Email Address
    - Recipient Name & Email Address
    - Return Path
    - Date & Time Sent
    - SPF, DKIM, and DMARC verification
    - Links, Attachments, and Attachment Hashes
- Outputs all this data into a .txt file in the output folder.

## Dependencies
---
- Python 3.13 or above.
https://www.python.org/downloads/ Download the latest *stable* version(not pre-release, etc). When installing, check the "add to PATH" option. I'm pretty sure there was one.

- Python dependencies:
    - dnspython
    - dkimpy
    - beautifulsoup4
    - extract-msg
    - typing

Use "pip install" then the dependency name as an argument on Command Prompt to install.

## How to Use
---
- Download the repo as a .zip file. Extract all of it out.
- When your File Explorer is on the directory the .py program is on, click on the directory bar and type "cmd".
- Type in the command "py phisherman.py" to run it.
- Ensure files you wanna process are in input folder, run the program on Command Prompt, and it will extract text in output folder.
- Data is now available for scanning or inspection.

## Issues
---
- Recipient email address shows up on "Recipient Name" instead of "Recipient Address". Currently determining if this is an email thing or a skill issue from me.

## Roadmap
---
- Extraction of actual email content in raw text, if any.

## Version Control
---
v1.1 - 
- added SPF/DKIM/DMARC verification
- can now extract most links & attachments
- can now extract most attachment hashes

v1.0 - initial commit
