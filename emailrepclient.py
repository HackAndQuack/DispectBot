import emailrep
from emailrep import EmailRep
from dotenv import load_dotenv
import os

load_dotenv()
#Imports API
emailrep = EmailRep((os.getenv('EMAIL_REP_API')))

#Scans email and return response
def scan_email(email:str) -> str:
    data = emailrep.query(email)

    email_response = ('Email ' + str(data['email'])
             + '\nReputation: ' + str(data['reputation'])
             + '\nSuspicious: ' + str(data['suspicious'])
             + '\nReferences: ' + str(data['references'])
             + '\nDetails: ')

    for x in data['details']:
        email_response += '\n'+ x + ': '
        email_response += (str(data['details'][x]))

    return email_response

#Reports the email and returns static response
def report_email(email:str,tags:[],description:str) -> str:
    emailrep.report(email,tags,description)
    return "Report successful"

#Returns what Tags would be needed for the tags[] section
def show_tags() -> str:
    tag_description = '''account_takeover - Legitimate email has been taken over by a malicious actor\n
    bec - Business email compromise, whaling, contact impersonation/display name spoofing\n
    brand_impersonation - Impersonating a well-known brand (e.g. Paypal, Microsoft, Google, etc.)\n
    browser_exploit - The hosted website serves an exploit\n
    credential_phishing - Attempting to steal user credentials\n
    generic_phishing - Generic phishing, should only be used if others do not apply or a more specific determination can not be made or would be too difficult\n
    malware - Malicious documents and droppers. Can be direct attachments, indirect free file hosting sites or droppers from malicious websites\n
    scam - Catch-all for scams. Sextortion, payment scams, lottery scams, investment scams, fake bank scams, etc.\n
    spam - Unsolicited spam or spammy behavior (e.g. forum submissions, unwanted bulk email)\n
    spoofed - Forged sender email (e.g. the envelope from is different than the header from)\n
    task_request - Request that the recipient perform a task (e.g. gift card purchase, update payroll, send w-2s, etc.)\n
    threat_actor - Threat actor/owner of phishing kit'''

    return tag_description