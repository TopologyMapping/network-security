# Analysis of Shodan probing modules and ports (UFMG only)

import json
import os

from ipaddress import ip_network

# Ufmg ips directory
directory = "../data_shodan/"

# Modules found across all scans, unique ips and services
uniqueModules = {}
uniqueIps = {}
servicesProvided = []

for file in os.scandir(directory):
    # Skip dirs and non-json files
    if (not file.is_file() or not file.path.endswith(".json")):
        continue

    data = json.load(open(file.path, 'r'))

    # Get number of modules and port range
    for scan in data:

        keysDict = scan.keys()
        if not servicesProvided.__contains__(keysDict):
            servicesProvided.append(keysDict)
        
        ip = scan["ip_str"]

        if uniqueIps.__contains__(ip):
            if ("cpe23" in scan): 
                cpe = (scan["cpe23"])
                for j in cpe:
                    uniqueIps[ip].add(j)
        else: 
            uniqueIps[ip] = set()
            if ("cpe23" in scan): 
                cpe = (scan["cpe23"])
                for j in cpe:
                    uniqueIps[ip].add(j)

        module = scan["_shodan"]["module"]

        if uniqueModules.__contains__(module):
            uniqueModules[module].add(scan["port"])
        else:
            uniqueModules[module] = set()
            uniqueModules[module].add(scan["port"])

# Ports found across all modules
uniquePorts = set()

servicesProvided = [list(keysDict) for keysDict in servicesProvided]

formatedServicesProvided = []
for i in servicesProvided:
    formatedServicesProvided.extend(i)

formatedServicesProvided = list(set(formatedServicesProvided))

# write info collected in a file
with open('../results/modules_and_ports_shodan.txt', 'w') as file:
    for module, ports in uniqueModules.items():
        result_string = "{:<20} ({:d} ports) {}".format(module, len(ports), ports) 
        file.write(result_string)

        uniquePorts.update(ports)
        file.write("\n")
    file.write("Unique modules:" + str(len(uniqueModules)))
    file.write("\n\n")
    file.write("Services provided:" + str(formatedServicesProvided))
    file.write("\n\n")
    file.write("Unique Ips:" + str(len(uniqueIps)))
    file.write("\n\n")
    file.write("IPS: ")
    file.write("\n\n")
    for ip, cpe in uniqueIps.items():
        file.write(str(ip) + " ")
        if len(cpe) != 0:
            file.write(str(cpe))
        file.write("\n")