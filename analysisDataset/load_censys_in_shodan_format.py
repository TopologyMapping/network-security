# Analysis of Shodan probing modules and ports (UFMG only)

import json
import os
import argparse
from typing import Dict, Union, List

def return_input_parameters():
    parser = argparse.ArgumentParser(description='Inform the directory with the input data and the directory to store the output.')
    parser.add_argument('inputDirectory', type=str, help='directory with input data')
    parser.add_argument('outputDirectory', type=str, help='directory to store output data')
    args = parser.parse_args()
    
    return args

def load_censys_in_shodan_format(args):
    # Ufmg ips directory
    directory = args.inputDirectory

    if not (os.path.exists(directory) and os.path.isdir(directory)):
        raise Exception('Directory not valid or not exists')

    CPE_FIELD_IN_SHODAN = 'cpe23'
    IP_FIELD_IN_SHODAN = 'ip_str'
    PORT_FIELD_IN_SHODAN = 'port'
    MODULE_FIELD_IN_SHODAN = 'module'
    PREFIX_MODULE_FIELD_IN_SHODAN = '_shodan'

    infoCensysToShodanFormat : List[str]= []

    fileName = ''
    for file in os.scandir(directory):
        fileName, _ = os.path.splitext(file.name)

        # Skip dirs and non-json files
        if (not file.is_file() or not file.path.endswith(".json")):
            continue

        data = json.load(open(file.path, 'r'))

        # read all scans
        for scan in data:

            # info can be a Dict of strings or Dict of Dicts
            infoScanned : Dict[str, Union[str, Dict[str, str]]] = {}

            # all lines above are reading data in censys and store as shodan format
            ip = scan["ip"]
            cpe = []

            if ("operating_system" in scan) and ("cpe" in scan["operating_system"]):
                cpe.append(scan["operating_system"]["cpe"])
            
            location = ''
            if ('location' in scan):
                location = {
                    'city': scan['location']['city'],
                    'longitude': scan['location']['coordinates']['longitude'],
                    'latitude': scan['location']['coordinates']['latitude'],
                    'country_code': scan['location']['country_code'],
                    'country_name': scan['location']['country'],
                    'continent': scan['location']['continent'],
                    'province': scan['location']['province'],    
                }
            
            operating_system = ''
            product = ''
            if ('operating_system' in scan):
                if ('vendor' in scan['operating_system']):
                    operating_system = {
                        'vendor': scan['operating_system']['vendor']
                    }
                if ('product' in scan['operating_system']):
                    product = scan['operating_system']['product']

            autonomous_system = ''
            org = ''
            asn = ''
            if ('autonomous_system' in scan): 
                autonomous_system = scan ['autonomous_system']
                org = scan ['autonomous_system']['name']
                asn = scan['autonomous_system']['asn']

            timestamp = ''
            if ('last_updated_at' in scan):
                timestamp = scan['last_updated_at']

            dns = ''
            if ('dns' in scan):
                dns = scan['dns']

            # goes through all services and sotres output 
            for i in scan["services"]:
                module = i["extended_service_name"]
                port = i["port"]
            
                infoScanned[IP_FIELD_IN_SHODAN] = ip
                infoScanned[CPE_FIELD_IN_SHODAN] = cpe
                infoScanned[PORT_FIELD_IN_SHODAN] = port
                infoScanned['location'] = location
                infoScanned['operating_system'] = operating_system
                infoScanned['autonomous_system'] = autonomous_system
                infoScanned['timestamp'] = timestamp
                infoScanned['asn'] = asn
                infoScanned['dns'] = dns
                infoScanned['product'] = product
                infoScanned['org'] = org

                infoScanned[PREFIX_MODULE_FIELD_IN_SHODAN] = dict()
                infoScanned[PREFIX_MODULE_FIELD_IN_SHODAN][MODULE_FIELD_IN_SHODAN] = module

                infoCensysToShodanFormat.append(infoScanned)
                infoScanned = {} # clean the dict
        
    outputDirectory = args.outputDirectory
    with open(f'{outputDirectory}{fileName}_formated.json', 'w') as file:
        json.dump(infoCensysToShodanFormat, file, indent=6)

if __name__ == "__main__":
    args = return_input_parameters()
    load_censys_in_shodan_format(args)
        