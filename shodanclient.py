from dotenv import load_dotenv , find_dotenv
import os
from shodan import Shodan
import ipaddress
import requests
import json

shodan_client = Shodan(os.getenv('SHODAN_API'))

#Checks if IP-Address is Valid
def check(ip) -> bool:
    #Use the ip_address function from the ipaddress module to check if the input is a valid IP address
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
    #If the input is not a valid IP address, catch the exception and print an error message
        return False

#Scans Host and returns it cleaned and formatted
def scan_host(ip:str) -> str:
    data_host = shodan_client.host(ip)
    host_str = parse_and_sort_scan_host(data_host)
    return host_str

#formats the response file from the host scan
def parse_and_sort_scan_host(data_host:dict) -> str:
    ip_reponse = ('Location: \n ---------' 
                  + '\nArea Code: ' + (str(data_host['area_code']))
                  + '\nCity: ' + (str(data_host['city']))
                  + '\nCountry Code: ' + (str(data_host['country_code']))
                  + '\nCountry Name: ' + (str(data_host['country_name']))
                  + '\nLatitude: ' + (str(data_host['latitude']))
                  + '\nLongitude: ' + (str(data_host['longitude']))
                  + '\nRegion Code: ' + (str(data_host['region_code']))
                  + '\n\nData: \n ---------'
                  + '\nDomains: ' + (str(data_host['domains']))
                  + '\nHost Names: ' + (str(data_host['hostnames']))
                  + '\nIP: ' + (str(data_host['ip']))
                  + '\nIP String: ' + (str(data_host['ip_str']))
                  + '\nISP: ' + (str(data_host['isp']))
                  + '\nORG: ' + (str(data_host['org']))
                  + '\nOS: ' + (str(data_host['os']))
                  + '\nPorts: ' + (str(data_host['ports']))
                  + '\nTags: ' + (str(data_host['tags']))
                  )

    return ip_reponse

#Scans API info and gives stats
def get_api_info() -> str:
    api_data = shodan_client.info()
    api_parse = parse_and_sort_api_info(api_data)
    return api_parse

#Formats the response file from the api_info scan
def parse_and_sort_api_info(api_data:dict) -> str:
    api_response = ('Info: \n ---------'
                    + '\nScan Credits: ' + (str(api_data['scan_credits']))
                    + '\nPlan: ' + (str(api_data['plan']))
                    + '\nHTTPs: ' + (str(api_data['https']))
                    + '\nUnlocked: ' + (str(api_data['unlocked']))
                    + '\nQuery Credits: ' + (str(api_data['query_credits']))
                    + '\nMonitored IPs: ' + (str(api_data['monitored_ips']))
                    + '\nUnlocked Left: ' + (str(api_data['unlocked_left']))
                    + '\nTelnet: ' + (str(api_data['telnet']))
                    )
    return api_response
    
#Scans Reverse DNS info
def reverse_dns_info(ip_list:str) -> str:
    ip_parameters = {
        'ips': ip_list,
        'key': (str(os.getenv('SHODAN_API')))
    }

    url = "https://api.shodan.io/dns/reverse?"
    response = requests.get(url,params=ip_parameters)
    response_data = response.json()
    response = parse_and_sort_reverse_dns(response_data)
    return response

#Formats the response file from the reverse_dns_info scan
def parse_and_sort_reverse_dns(data:json) -> str:
    response_parse = 'Reverse DNS Lookup: \n----------------'
    for x in data:
        response_parse += ('\n' + str(x) + ': ' + str(data[x]))
    return response_parse

def dns_lookup_info(ip_list:str) -> str:
    ip_parameters = {
        'hostnames': ip_list,
        'key': (str(os.getenv('SHODAN_API')))
    }
    url = "https://api.shodan.io/dns/resolve?"
    response = requests.get(url,params=ip_parameters)
    response_data = response.json()
    response = parse_and_sort_dns_lookup(response_data)
    return response

def parse_and_sort_dns_lookup(data:json) -> str:
    response_parse = 'DNS Lookup: \n----------------'
    for x in data:
        response_parse += ('\n' + str(x) + ': ' + str(data[x]))
    return response_parse