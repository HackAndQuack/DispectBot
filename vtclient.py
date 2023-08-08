import vt 
import json
import nest_asyncio
import requests

nest_asyncio.apply()

def set_vt_token(token:str):
    global vt_token
    vt_token = token
    global vt_client
    vt_client = vt.Client(token)


def scan_for_json(url:str) -> dict:
    """Scans a URL using Virustotal API

    Args:
        url (str): The URL to scan

    Returns:
        dict: A dictionary of the JSON output from VirusTotal
    """
    analysis = vt_client.scan_url(url)
    while True:
        analysis = vt_client.get_object("/analyses/{}", analysis.id)
        print(f'Analysis status: {analysis.status}')
        if analysis.status == "completed":
            scan_result = str(analysis.get('results'))
            break
    # Change every apostraphe to a quotation mark to convert the results to JSON 
    scan_result = scan_result.replace('\'', '"')
    # Parse JSON file to filter information
    scan_parsed = json.loads(scan_result)
    return scan_parsed


def get_clean_percentage(scan_parsed:dict) -> int:
    """Gets a percentage of "clean" outputs from a VirusTotal JSON scan

    Args:
        scan_parsed (dict): The VirusTotal scan JSON (obtained from scan_for_json)

    Returns:
        int: A percentage of clean outputs from engines 
    """
    counter = 0
    for key in scan_parsed:
        if scan_parsed[key]["result"] == 'clean':
            counter += 1

    return (counter/len(scan_parsed))*100


def parse_and_sort(scan_parsed:dict, verbose:bool) -> str:
    """Parses through a VirusTotal JSON output, sorts based on severity, and formats a 
    string ready to be read by humans

    Args:
        scan_parsed (dict): The VirusTotal scan JSON (obtained from scan_for_json)

    Returns:
        str: nicely formatted VirusTotal output
    """
    scan_list = list()
    for key in scan_parsed:
        #print(f'{scan_parsed[key]["engine_name"]} result: {scan_parsed[key]["result"]}')
        scan_list.append(f'{scan_parsed[key]["engine_name"]} result: {scan_parsed[key]["result"]}')

    # Sort scan_list based on severity
    scan_list_clean = list()
    scan_list_unrated = list()
    scan_list_malicious = list()
    scan_list_malware = list()
    for entry in scan_list:
        if 'clean' in entry[entry.index(':'):]:
            scan_list_clean.append(entry)
        if 'unrated' in entry[entry.index(':'):]:
            scan_list_unrated.append(entry)
        if 'malicious' in entry[entry.index(':'):]:
            scan_list_malicious.append(entry)
        if 'malware' in entry[entry.index(':'):]:
            scan_list_malware.append(entry)
    scan_list = list()
    for entry in scan_list_malware:
        scan_list.append(entry)
    for entry in scan_list_malicious:
        scan_list.append(entry)
    for entry in scan_list_unrated:
        scan_list.append(entry)
    for entry in scan_list_clean:
        scan_list.append(entry)

    # Format scan_list to string
    scan_str = ('Clean: ' + str(len(scan_list_clean)) + '(' + str(round((len(scan_list_clean)/len(scan_list))*100)) +'%)'
                + '\nUnrated: ' + str(len(scan_list_unrated)) + '(' + str(round((len(scan_list_unrated)/len(scan_list))*100)) +'%)'
                + '\nMalicious: ' + str(len(scan_list_malicious)) + '(' + str(round((len(scan_list_malicious)/len(scan_list))*100)) +'%)'
                + '\nMalware: ' + str(len(scan_list_malware)) + '(' + str(round((len(scan_list_malware)/len(scan_list))*100)) +'%)')
    
    if verbose: 
        scan_str += '\n' + ('-'*20) + '\n'
        for entry in scan_list:
            if 'clean' in entry[entry.index(':'):]:
                scan_str += ':white_check_mark: '
            if 'unrated' in entry[entry.index(':'):]:
                scan_str += ':grey_question: '
            if 'malicious' in entry[entry.index(':'):]:
                scan_str += ':interrobang: '
            if 'malware' in entry[entry.index(':'):]:
                scan_str += ':fire: '
            scan_str += entry + '\n'
    return scan_str

#Gets a list of popular threat categories
def get_threat_categories() -> str:
    url = "https://www.virustotal.com/api/v3/popular_threat_categories"

    headers = {
        "accept": "application/json",
        "X-Apikey": (vt_token)
    }

    response = requests.get(url, headers=headers)
    response_data = response.json()
    parse_data = parse_and_sort_threat_categories(response_data)
    return parse_data
#Formats json file
def parse_and_sort_threat_categories(response_data:json) -> str: 
    parse_data = 'Threats: \n--------'
    for x in response_data['data']:
        parse_data += ('\n' + str(x))
    return parse_data
