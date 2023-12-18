# Analysis of Shodan probing modules and ports (UFMG only)
# This code works for Censys data too (but need to be formatted in Shodan style, check the 'load_censys_in_shodan_format.py' file)

import json
import os
from typing import Dict, Set, List
import argparse

def return_input_parameters():
    parser = argparse.ArgumentParser(description='Inform the directory with the data and the path to the output.')
    parser.add_argument('directory', type=str, help='directory with data')
    parser.add_argument('outputPath', type=str, help='path to the output file')
    args = parser.parse_args()
    
    return args

def probe_data_shodan_and_censys (args): 
    # Ufmg ips directory
    directory = args.directory

    if not (os.path.exists(directory) and os.path.isdir(directory)):
        raise Exception('Directory not valid or not exists')

    # Modules found across all scans, unique ips and services
    modulesShodan : Dict[str, Set[str]] = {}
    ipsScanned : Dict[str, str] = {}
    servicesProvided : List[str] = []

    for file in os.scandir(directory):
        # Skip dirs and non-json files
        if (not file.is_file() or not file.path.endswith(".json")):
            continue

        data = json.load(open(file.path, 'r'))

        # Get number of modules and port range
        for scan in data:

            keysDict = scan.keys()
            if not (keysDict) in servicesProvided:
                servicesProvided.append(keysDict)
            
            ip = scan["ip_str"]

            if (ip) in ipsScanned:
                if ("cpe23" in scan): 
                    cpe = (scan["cpe23"])
                    for j in cpe:
                        ipsScanned[ip].add(j)
            else: 
                ipsScanned[ip] = set()
                if ("cpe23" in scan): 
                    cpe = (scan["cpe23"])
                    for j in cpe:
                        ipsScanned[ip].add(j)

            module = scan["_shodan"]["module"]

            if (module) in modulesShodan:
                modulesShodan[module].add(scan["port"])
            else:
                modulesShodan[module] = set()
                modulesShodan[module].add(scan["port"])


    # different info collected 
    servicesProvided = [list(keysDict) for keysDict in servicesProvided]

    formatedServicesProvided = []
    for i in servicesProvided:
        formatedServicesProvided.extend(i)

    formatedServicesProvided = list(set(formatedServicesProvided))

    # format data to build json
    modules_shodan_serializable = {
        module: {"ports": list(ports), "count": len(ports)} for module, ports in modulesShodan.items()
    }

    ips_scanned_serializable = {
        ip: {"cpe": list(cpe)} for ip, cpe in ipsScanned.items()
    }

    data_to_be_dumped = {
        "modulesShodan": modules_shodan_serializable,
        "uniqueModulesCount": len(modulesShodan),
        "servicesProvided": formatedServicesProvided,
        "uniqueIpsCount": len(ipsScanned),
        "ipsScanned": ips_scanned_serializable
    }

    # write info collected in a file
    path_output_file = args.outputPath
    with open(path_output_file, 'w') as file:
        json.dump(data_to_be_dumped, file, indent=4)

if __name__ == "__main__":
    args = return_input_parameters()
    probe_data_shodan_and_censys(args)