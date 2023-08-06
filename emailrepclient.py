import emailrep
from emailrep import EmailRep
from dotenv import load_dotenv
import os


load_dotenv()
emailrep = EmailRep((os.getenv('EMAIL_REP_API')))


def scan_email(email:str) -> str:
    data = emailrep.query(email)

    email_response = ('Email ' + data['email']
             + '\nReputation: ' + str(data['reputation'])
             + '\nSuspicious: ' + str(data['suspicious'])
             + '\nReferences: ' + str(data['references'])
             + '\nDetails: ')

    for x in data['details']:
        email_response += '\n'+ x + ': '
        email_response += (str(data['details'][x]))

    return email_response


def report_email(email:str):
    #emailrep --report email --tags "bec, maldoc" --description "Contact impersonation to CEO"
    # TODO: make this function
    print('Reporting email...')