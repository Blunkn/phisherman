# Phisherman
---
## Version 1.0.0
---

An email metadata extractor. Designed to determine if an email could be a phish or not.

Inspired by a program I happened upon during my military service.

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
- Python 3.7 or above.
https://www.python.org/downloads/ Download the latest *stable* version(not pre-release, etc). When installing, check the "add to PATH" option. I'm pretty sure there was one.

- Python dependencies:
    - dnspython
    - dkimpy
    - beautifulsoup4
    - extract-msg
    - typing

Use "pip install" then the dependency name as an argument on Command Prompt to install.
Example:
`pip install dnspython`

Alternatively, while on a command interpreter on the `packages` folder, run this command:
`pip install --find-links . --no-index *`
This installs pre-downloaded dependencies that come with this repo.

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
- N/A

## Version Control
---
1.0.0
- transition to semantic versioning
- added more elaborate docstrings for each function
- added .whl files of dependencies + requirements.txt in a "packages" folder

v1.3 -
- script can now extract email content, albeit with a lot of newlines
- attachments are now neatly saved into a folder with the email subject for its name

v1.2 -
- fixed naming conventions causing crashes
- fixed error handling not outputting exact errors

v1.1 - 
- added SPF/DKIM/DMARC verification
- can now extract most links & attachments
- can now extract most attachment hashes

v1.0 - initial commit
