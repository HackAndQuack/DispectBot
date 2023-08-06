from dotenv import load_dotenv , find_dotenv
import os
from shodan import Shodan

shodan_client = Shodan(os.getenv('SHODAN_API'))

def scan_host(ip:str) -> str:
    data = shodan_client.host(str)

    ip_reponse = ('Country Code: ' + data['country_code']
                + '\nCountry Name: ' + data['country_name']
                + '\nCity: ' + data['city']
                + )