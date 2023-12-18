# Motivation: Understand how the data are collected and the quantity / quality os measurements made for each ip
import argparse
import json
import os
from typing import List

def return_input_parameters():
    parser = argparse.ArgumentParser(description='Inform the directory with shodan data.')
    parser.add_argument('inputDirectory', type=str, help='directory with shodan data')
    parser.add_argument('outputPath', type=str, help='path to the output file')
    args = parser.parse_args()

    return args

def temporal_scan_ip_shodan(args):
    # Ufmg ips directory
    directory = args.inputDirectory

    if not (os.path.exists(directory) and os.path.isdir(directory)):
        raise Exception('Directory not valid or not exists')

    # info to be collected
    daysScan : dict() = {}
    uniqueIps : List[str] = [0]
    allIps : List[str] = []
    repeatedIpScan: List[str] = [0]
    ipScanedAgainOnTheSameDay : List[str]= [0]
    ipsScanned : List[str]= [0]
    index = 0

    # read file names first to order and open files in temporal order
    files = [file.name for file in os.scandir(directory) if file.is_file() and file.name.endswith(".json") and file.name.split('.')[1] ]
    sorted_files = sorted(files)

    for file in sorted_files:

        data = json.load(open(f"{directory}{file}", 'r'))

        # Get number of modules and port range
        for scan in data:      
            ip = scan["ip_str"]
            timestamp = scan["timestamp"][:10] #truncate date format to get just date, not hours
            if (timestamp < '2023-11-00'): # Ignore data whose date is not in the month to be analyzed
                continue
            ipsScanned[index] += 1

            if ip in daysScan:
                
                if ((timestamp) in (daysScan[ip]['timestamp'])):
                    ipScanedAgainOnTheSameDay[index] += 1
                else:
                    repeatedIpScan[index] += 1
                
                daysScan[ip]['timestamp'].add(timestamp)
                daysScan[ip]['scans'] += 1
            else: 
                daysScan[ip] = set()
                daysScan[ip] = {'timestamp': {timestamp}, 'scans': 1}

            if (not((ip) in allIps)):
                allIps.append(ip)
                uniqueIps[index] += 1

        # prepare variables for the next file
        index +=1
        ipsScanned.append(0)
        uniqueIps.append(0)
        repeatedIpScan.append(0)
        ipScanedAgainOnTheSameDay.append(0)

    for ip, data in daysScan.items():
        daysScan[ip]['timestamp'] = sorted(data['timestamp'])

    #sort ips by the number os scans
    sorted_daysScan = sorted(daysScan.items(), key=lambda x: x[1]['scans'], reverse=True)

    # group data to write json
    data = {
        "days_summary": [
            {
                "Day": i + 1,
                "IpsScanned": ipsScanned[i],
                "UniqueIps": uniqueIps[i],
                "RepeatedIpScan": repeatedIpScan[i],
                "IpScanedAgainOnTheSameDay": ipScanedAgainOnTheSameDay[i]
            } for i in range(len(ipsScanned)-1)
        ],
        "sorted_daysScan": sorted_daysScan
    }
    path_output_file = args.outputPath
    with open(path_output_file, 'w') as file:
        json.dump(data, file, indent=6)

if __name__ == "__main__":
    args = return_input_parameters()
    temporal_scan_ip_shodan(args)
        

