# Analysis of UFMG IP's over a short time window

import json
import itertools
import bz2
import pickle

from ipaddress import ip_network

# UFMG ips
jsonUFMG = []

# UFMG subnet
ipUFMG = ip_network('150.164.0.0/16')

# Shodan scan window
month = 10
startDay = 1
timespanDays = 14

# Stuff found
analysisData = {}

# Unique ips cumulative sum
uniqueIpSum = 0
uniquePairIpModuleSum = 0

# Unique ips set
uniqueIps = set()
uniquePairsIpModule = set()

for d in range(timespanDays):
    day = startDay + d
    filename = f"../storage/datasets/survey/downloaded/BR.2023{str(month).rjust(2, '0')}{str(day).rjust(2, '0')}.json.bz2"

    # Iter through every dataset
    f = bz2.open(filename, 'rt')

    # Unique ips found for this day
    totalIpFound = 0
    uniqueIpFound = 0
    uniquePairIpModuleFound = 0

    for line in f:
        singleJson = json.loads(line)

        ip           = singleJson.get("ip_str")
        module       = singleJson.get("_shodan").get("module")

        # Match only UFMG ips
        if (ip != None and ip_network(ip).subnet_of(ipUFMG)):
            if not uniqueIps.__contains__(ip):
                uniqueIpFound += 1
                uniqueIps.add(ip)
            
            if not uniquePairsIpModule.__contains__((ip, module)):
                uniquePairIpModuleFound += 1
                uniquePairsIpModule.add((ip, module))
            
            totalIpFound += 1

    # Update cumulative sum
    uniqueIpSum += uniqueIpFound 
    uniquePairIpModuleSum += uniquePairIpModuleFound

    # Store data for this day
    data = {}
    data["total_ips_found"]            = totalIpFound
    data["unique_ips"]                 = uniqueIpFound
    data["unique_pairs_ip_module"]     = uniquePairIpModuleFound
    data["unique_ips_sum"]             = uniqueIpSum
    data["unique_pairs_ip_module_sum"] = uniquePairIpModuleSum
   
    analysisData[f"2023-{str(month).rjust(2, '0')}-{str(day).rjust(2, '0')}"] = data

    print(f"Finished {d + 1} of {timespanDays}")

# Quick look
for k, v in analysisData.items():
    print("\n", k)
    for kk, vv in v.items():
        print("    ", kk, ":", vv)

# Dump data for later use
pickle.dump(analysisData,        open('analysisData.pickle', 'wb'))
pickle.dump(uniqueIps,           open('uniqueIps.pickle', 'wb'))
pickle.dump(uniquePairsIpModule, open('uniquePairsIpModule.pickle', 'wb'))