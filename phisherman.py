import os, re, email, datetime, sys, hashlib
from email import policy
from extract_msg import Message
from pathlib import Path
from typing import Dict, Optional, Union
from urllib.parse import unquote
from bs4 import BeautifulSoup

from mods.authentication import verify_dkim, verify_dmarc, verify_spf

class Phisherman:
    def __init__(self):
        self.input = Path("input")
        self.output = Path("output")

        # create folders if missing
        self.input.mkdir(exist_ok=True)
        self.output.mkdir(exist_ok=True)

    def get_hash(self, data:bytes) -> Dict[str, str]:
        """get MD5, SHA1, SHA256 hashes"""
        return {
            'md5':hashlib.md5(data).hexdigest(),
            'sha1':hashlib.sha1(data).hexdigest(),
            'sha256':hashlib.sha256(data).hexdigest()
        }
    
    def get_links(self, content:str) -> list:
        """get links"""
        regex = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        
        # Find all URLs and decode any URL encoding
        links = []
        for i in re.finditer(regex, content):
            decoded = unquote(i.group())
            if decoded not in links:
                links.append(decoded)
        return links
    
    def get_attachments_eml(self, msg) -> list:
        """extract gmail attachments"""
        attachments = []
        
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            
            filename = part.get_filename()
            if filename:
                data = part.get_payload(decode=True)
                if data:
                    attachment = {
                        'filename': filename,
                        'content_type': part.get_content_type(),
                        'size': len(data),
                        'hashes': self.get_hash(data)
                    }
                    
                    # Save attachment
                    attachment_path = self.output / f"{self.sanitise_filename(filename)}"
                    with open(attachment_path, 'wb') as f:
                        f.write(data)
                    
                    attachment['saved_path'] = str(attachment_path)
                    attachments.append(attachment)
                    
        return attachments

    def get_attachments_msg(self, msg) -> list:
        """extract outlook attachments"""
        attachments = []
        
        for attachment in msg.attachments:
            data = attachment.data
            if data:
                attachment_info = {
                    'filename': attachment.filename,
                    'content_type': attachment.mimetype,
                    'size': len(data),
                    'hashes': self.get_hash(data)
                }
                
                # Save attachment
                attachment_path = self.output / f"{self.sanitise_filename(attachment.filename)}"
                with open(attachment_path, 'wb') as f:
                    f.write(data)
                
                attachment_info['saved_path'] = str(attachment_path)
                attachments.append(attachment_info)
                
        return attachments

    def sanitise_filename(self, filename):
        """sanitise input filename for output lol"""
        name = re.sub(r'[<>:"/\\|?*]', '_', filename)
        name = name.strip('. ')
        return name if name else 'Untitled'
    
    def extract_email_address(self, email_string: str) -> tuple:
        """extract email address and display name"""
        if not email_string: # checks if input is empty
            return ('', '')
        
        match = re.match(r'"?([^"<]*)"?\s*<?([^>]*)>?', email_string)
        if match:
            name, address = match.groups()
            return (name.strip(), address.strip()) # returns name & email address
        return ('', email_string.strip()) # else, return only email address

    # --- PARSERS ---
    def parse_eml(self, emlpath):
        """parse gmail emails"""
        try:
            with open(emlpath, 'rb') as f:
                content = f.read()
                msg = email.message_from_bytes(content, policy=policy.default)

            sender_name, sender_addr = self.extract_email_address(msg.get('from', ''))
            recipient_name, recipient_addr = self.extract_email_address(msg.get('to', ''))
            return_name, return_addr = self.extract_email_address(msg.get('return-path', ''))
            domain = sender_addr.split('@')[1] if '@' in sender_addr else ''

            # auth results
            spf = verify_spf(domain, msg.get('received-spf', ''))
            dkim = verify_dkim(content, domain)
            dmarc = verify_dmarc(domain)

            # get links
            links = []
            for i in msg.walk():
                if i.get_content_type() == 'text/plain':
                    links.extend(self.get_links(i.get_content()))
                elif i.get_content_type() == 'text/html':
                    soup = BeautifulSoup(i.get_content(), 'html.parser')
                    for j in soup.find_all('a'):
                        href=j.get('href')
                        if href and href.startswith(('http://', 'https://')):
                            links.append(href)

            headers = {
                'subject':msg.get('subject', 'Untitled'), # subject & date taken from email itself, everyth else use func
                'sender_name':sender_name,
                'sender_addr':sender_addr,
                'recipient_name':recipient_name,
                'recipient_addr':recipient_addr,
                'return_path':return_addr,
                'date':msg.get('date', ''),
                'auth':{
                    'spf':spf,
                    'dkim':dkim,
                    'dmarc':dmarc
                },
                'links':list(set(links)), # set used to remove dupes
                'attachments':self.get_attachments_eml(msg)
            }

            return headers
        
        except Exception as e:
            return f"Error: {str(e)}"
        
    def parse_msg(self, msgpath):
        """parse outlook emails"""
        try:
            msg = Message(str(msgpath))

            sender_name, sender_addr = self.extract_email_address(msg.sender)
            recipient_name, recipient_addr = self.extract_email_address(msg.to)
            return_name, return_addr = self.extract_email_address(msg.reply_to)
            domain = sender_addr.split('@')[1] if '@' in sender_addr else ''

            spf = verify_spf(domain, '')
            dmarc = verify_dmarc(domain)

            # get links
            links = []
            if msg.body:
                links.extend(self.get_links(msg.body))
            if msg.html:
                soup = BeautifulSoup(msg.html, 'html.parser')
                for link in soup.find_all('a'):
                    href = link.get('href')
                    if href and href.startswith(('http://', 'https://')):
                        links.append(href)

            headers = {
                'subject':msg.subject or 'Untitled',
                'sender_name':sender_name,
                'sender_addr':sender_addr,
                'recipient_name':recipient_name,
                'recipient_addr':recipient_addr,
                'return_path':return_addr,
                'date': msg.date,
                'auth':{
                    'spf':spf,
                    'dkim':"Not available",
                    'dmarc':dmarc
                },
                'links':list(set(links)),
                'attachments':self.get_attachments_msg(msg)
            }
            return headers
        
        except Exception as e:
            return f"Error: {str(e)}"
        
    # --- PROCESSORS ---
    def save_text(self, headers: Dict[str, str], filename: str) -> Path:
        """saves content to output dir & file"""
        output_file = self.output / f"{self.sanitise_filename(filename)}_results.txt"
        with open(output_file, 'a', encoding='utf-8') as f:
            # basic headers
            f.write(f"Subject: {headers.get('subject', 'N/A')}\n")
            f.write(f"Sender Name: {headers.get('sender_name', 'N/A')}\n")
            f.write(f"Sender Address: {headers.get('sender_addr', 'N/A')}\n")
            f.write(f"Recipient Name: {headers.get('recipient_name', 'N/A')}\n")
            f.write(f"Recipient Address: {headers.get('recipient_addr', 'N/A')}\n")
            f.write(f"Return Path: {headers.get('return_path', 'N/A')}\n")
            f.write(f"Date: {headers.get('date', 'N/A')}\n\n")

            # auth results
            auth = headers.get('auth', {})
            f.write("\nSPF:\n")
            spf = auth.get('spf', {})
            f.write(f"Status: {spf.get('status', 'N/A')}\n")
            f.write(f"Details: {spf.get('details', 'N/A')}\n")

            f.write("\nDKIM:\n")
            dkim = auth.get('dkim', {})
            f.write(f"Status: {dkim.get('status', 'N/A')}\n")
            f.write(f"Details: {dkim.get('details', 'N/A')}\n")

            f.write("\nDMARC:\n")
            dmarc = auth.get('dmarc', {})
            f.write(f"Status: {dmarc.get('status', 'N/A')}\n")
            f.write(f"Details: {dmarc.get('details','N/A')}\n")

            # links
            f.write("\nLinks found:\n")
            if headers.get('links'):
                for i in headers['links']:
                    f.write(f"{i}\n")
            else:
                f.write("No links found.\n")

            # attachments
            f.write('\nAttachments found:\n')
            if headers.get('attachments'):
                for i in headers['attachments']:
                    f.write(f"\nFilename: {i['filename']}\n")
                    f.write(f"Content-Type: {i['content_type']}\n")
                    f.write(f"Size: {i['size']} bytes\n")
                    f.write("Hashes:\n")
                    f.write(f"  MD5: {i['hashes']['md5']}\n")
                    f.write(f"  SHA1: {i['hashes']['sha1']}\n")
                    f.write(f"  SHA256: {i['hashes']['sha256']}\n")
            else:
                f.write("No attachments found.\n")

        return output_file

    def process_email(self) -> int:
        """determine whether email is .eml or .msg, and handle it appropriately"""
        processed = 0

        for f in self.input.iterdir():
            if not f.is_file(): # ignore subdirs
                continue

            if f.suffix.lower() == '.eml': # if email is from gmail,
                headers = self.parse_eml(f)
            elif f.suffix.lower() == '.msg': # if email is from outlook,
                headers = self.parse_msg(f)
            else:
                continue

            if isinstance(headers, dict): # if anything got extracted,
                output_path = self.save_text(headers, f.name)
                processed+=1
                print(f"Email processed. Saved to {output_path}\n")
                print(f"Emails processed: {processed}")
            else:
                print(f"Error processing {f.name}: {headers}")

        return processed
    
def help():
    """Display help information about the program."""
    help_text = """
    Phisherman - Email Metadata Extraction Tool
    
    Usage:
    - Place .eml or .msg files in the 'input' directory
    - Run the program to extract metadata
    - Results will be saved in the 'output' directory
    """
    print(help_text)

def menu():
    print("\nPhisherman")
    print("Please choose an option:")
    print("1 - Process emails")
    print("2 - Help")
    print("3 - Exit")
    return input('Select an option (1-3): ')

def main():
    fishe = Phisherman()

    while True:
        choice = menu().strip()
        if choice == '1':
            res = fishe.process_email()
            if res == 0:
                print(f"\nInput directory is empty")
            else:
                print(f"\nProcessed {res} files")
        elif choice == '2':
            help()
        elif choice == '3':
            print("\nExiting...")
            break
        else:
            print("\nInvalid option.")

if __name__ == '__main__':
    main()
