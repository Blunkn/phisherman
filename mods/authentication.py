import dns.resolver, dkim
from typing import Dict, Optional

# --- SPF ---
# SPF means sender policy framework
# SPF helps verify if the server sending an email is authorized to send mail for that domain, reducing email spoofing.
def verify_spf(sender_domain:str, sender_ip:str) -> Dict[str, Optional[str]]:
    """
    verify SPF record for email
    """
    try:
        if not sender_domain or not sender_ip: # account for missing domain or IP
            return {
                'status':'Error',
                'record':None,
                'details':'Missing domain/IP'
            }
        
        resolver = dns.resolver.Resolver()
        try:
            records = resolver.resolve(sender_domain, 'TXT')
        except dns.resolver.NXDOMAIN:
            return {
                'status':'None',
                'record':None,
                'details':'Domain does not exist'
            }
        except dns.resolver.NoAnswer:
            return {
                'status':'None',
                'record':None,
                'details':'No SPF records found'
            }
        
        record = None
        for i in records:
            record_txt = i.to_text().strip('"')
            if record_txt.startswith('v=spf1'):
                record = record_txt
                break

        if not record:
            return {
                'status':'None',
                'record':None,
                'details':'No SPF records found'
            }
        
        return {
            'status':'Neutral',
            'record':record,
            'details':f"Found record: {record}"
        }
    
    except Exception as e:
        return {
            'status':'Error',
            'record':None,
            'details':f"Error: {str(e)}"
        }


# --- DKIM ---
# DKIM means domain keys identified mail

# DKIM adds a digital signature to emails that receivers can verify to 
# ensure the email wasn't altered in transit and came from the claimed domain.
def verify_dkim(content:bytes, domain:str) -> Dict[str, Optional[str]]:
    """
    verify DKIM signature
    """
    try:
        if not content:
            return {
                'status':'Error',
                'record':None,
                'details':'No email content provided'
            }
        
        try:
            is_valid = dkim.verify(content)
            if is_valid:
                return {
                    'status':'Pass',
                    'record':'DKIM signature valid',
                    'details':'Email signature verified'
                }
            else:
                return {
                    'status':'Fail',
                    'record':'DKIM signature invalid',
                    'details':'Verification failed'
                }
            
        except dkim.DKIMException:
            return {
                'status':'Error',
                'record':None,
                'details':f"Verification error: {str(dkim.DKIMException)}"
            }
        
    except Exception as e:
        return {
            'status':'Error',
            'record':None,
            'details':f"DKIM processing error: {str(e)}"
        }
    

# --- DMARC ---
# stands for domain-based message authentication, reporting, and conformance
# builds on SPF and DKIM by letting domain owners specify how to handle emails that fail authentication
def verify_dmarc(domain:str) -> Dict[str, Optional[str]]:
    """
    verify DMARC record
    """
    try:
        if not domain:
            return {
                'status':'Error',
                'record':None,
                'details':'No domain provided'
            }
        
        resolver = dns.resolver.Resolver()
        try:
            dmarcdomain = f"_dmarc.{domain}"
            dmarcrecord = resolver.resolve(dmarcdomain, 'TXT')
        except dns.resolver.NXDOMAIN:
            return {
                'status':'None',
                'record':None,
                'details':'No DMARC record found'
            }
        except dns.resolver.NoAnswer:
            return {
                'status':'None',
                'record':None,
                'details':'No DMARC records found'
            }
        
        record = None
        for i in dmarcrecord:
            record_txt = i.to_text().strip('"')
            if record_txt.startswith('v=DMARC1'):
                record = record_txt
                break

        if not record:
            return {
                'status':'None',
                'record':None,
                'details':'No DMARC record found'
            }
        
        # Parse basic DMARC policy
        policy = 'none'  # default
        for tag in record.split(';'):
            tag = tag.strip()
            if tag.startswith('p='):
                policy = tag.split('=')[1]
                break

        return {
            'status': 'pass',
            'record': record,
            'details': f'DMARC record found with policy: {policy}'
        }

    except Exception as e:
        return {
            'status': 'error',
            'record': None,
            'details': f'DMARC verification error: {str(e)}'
        }
