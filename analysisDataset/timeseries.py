# Analysis of UFMG IP's over a short time window

import json
import itertools
import bz2
import logging
import pickle
import argparse
from ipaddress import ip_network


def return_input_parameters():
    parser = argparse.ArgumentParser(description='Inform the month, start and end to be filtered. Pass the input directory to load data.')
    parser.add_argument('month', type=int, help='month to be analized')
    parser.add_argument('startDay', type=int, help='start day to be analized')
    parser.add_argument('endDay', type=int, help='end day to be analized')
    parser.add_argument('inputDirectory', type=int, help='directory with raw shodan data')
    args = parser.parse_args()
    
    return args

def timeseries(args): 

    # UFMG subnet
    ipUFMG = ip_network('150.164.0.0/16')

    # Shodan scan window
    month = args.month
    startDay = args.startDay
    timespanDays = args.endDay

    # Stuff found
    analysisData = {}

    # Unique ips cumulative sum
    uniqueIpSum = 0
    uniquePairIpModuleSum = 0

    # Unique ips set
    uniqueIps = set()
    uniquePairsIpModule = set()

    inputDirectory = args.inputDirectory

    for d in range(timespanDays):
        day = startDay + d
        filename = f"{inputDirectory}BR.2023{str(month).rjust(2, '0')}{str(day).rjust(2, '0')}.json.bz2"

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
    logging.debug(json.dumps(analysisData), indent=2)

    # Dump data for later use
    pickle.dump(analysisData,        open('analysisData.pickle', 'wb'))
    pickle.dump(uniqueIps,           open('uniqueIps.pickle', 'wb'))
    pickle.dump(uniquePairsIpModule, open('uniquePairsIpModule.pickle', 'wb'))


if __name__ == "__main__":
    args = return_input_parameters()
    timeseries(args)
        