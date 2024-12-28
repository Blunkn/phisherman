import os, re, email, datetime, sys
from email import policy
from extract_msg import Message
from pathlib import Path
from typing import Dict, Optional, Union

class Phisherman:
    def __init__(self):
        self.input = Path("input")
        self.output = Path("output")

        # create folders if missing
        self.input.mkdir(exist_ok=True)
        self.output.mkdir(exist_ok=True)

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

            headers = {
                'subject':msg.get('subject', 'Untitled'), # subject & date taken from email itself, everyth else use func
                'sender_name':sender_name,
                'sender_addr':sender_addr,
                'recipient_name':recipient_name,
                'recipient_addr':recipient_addr,
                'return_path':return_addr,
                'date':msg.get('date', '')
            }

            return headers
        
        except Exception:
            return f"Error: {str(Exception)}"
        
    def parse_msg(self, msgpath):
        """parse outlook emails"""
        try:
            msg = Message(str(msgpath))

            sender_name, sender_addr = self.extract_email_address(msg.sender)
            recipient_name, recipient_addr = self.extract_email_address(msg.to)
            return_name, return_addr = self.extract_email_address(msg.reply_to)
            domain = sender_addr.split('@')[1] if '@' in sender_addr else ''

            headers = {
                'subject':msg.subject or 'Untitled',
                'sender_name':sender_name,
                'sender_addr':sender_addr,
                'recipient_name':recipient_name,
                'recipient_addr':recipient_addr,
                'return_path':return_addr,
                'date': msg.date
            }
            return headers
        
        except Exception:
            return f"Error: {str(Exception)}"
        
    # --- PROCESSORS ---
    def save_text(self, headers: Dict[str, str], filename: str) -> Path:
        """saves content to output dir & file"""
        output_file = self.output / f"{self.sanitise_filename(filename)}_results.txt"
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(f"Subject: {headers.get('subject', 'N/A')}\n")
            f.write(f"Sender Name: {headers.get('sender_name', 'N/A')}\n")
            f.write(f"Sender Address: {headers.get('sender_addr', 'N/A')}\n")
            f.write(f"Recipient Name: {headers.get('recipient_name', 'N/A')}\n")
            f.write(f"Recipient Address: {headers.get('recipient_addr', 'N/A')}\n")
            f.write(f"Return Path: {headers.get('return_path', 'N/A')}\n")
            f.write(f"Date: {headers.get('date', 'N/A')}\n\n")
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

            if headers: # if anything got extracted,
                output_path = self.save_text(headers, f.name)
                processed+=1
                print(f"Email processed. Saved to {output_path}\n")
                print(f"Emails processed: {processed}")

        return processed
    
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
            pass
        elif choice == '3':
            print("\nExiting...")
            break
        else:
            print("\nInvalid option.")

if __name__ == '__main__':
    main()
