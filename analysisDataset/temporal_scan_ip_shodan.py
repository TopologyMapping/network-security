# Motivation: Understand how the data are collected and the quantity / quality os measurements made for each ip

import json
import os

# Ufmg ips directory
directory = "../ufmg_ips/"


# info to be collected
daysScan = {}
uniqueIps = [0]
allIps = []
repeatedIpScan = [0]
ipScanedAgainOnTheSameDay = [0]
ipsScanned = [0]
index = 0

#read file names first to order and open files in temporal order
files = [file.name for file in os.scandir(directory) if file.is_file() and file.name.endswith(".json")]
sorted_files = sorted(files, key=lambda x: os.path.getctime(os.path.join(directory, x)))

for file in sorted_files:

    data = json.load(open(f"../ufmg_ips/{file}", 'r'))

    # Get number of modules and port range
    for scan in data:      
        ip = scan["ip_str"]
        timestamp = scan["timestamp"][:10] #truncate date format to get just date, not hours
        if (timestamp < '2023-11-00'): # Ignore data whose date is not in the month to be analyzed
            continue
        ipsScanned[index] += 1

        if daysScan.__contains__(ip):
            
            if ((daysScan[ip]['timestamp'].__contains__(timestamp))):
                ipScanedAgainOnTheSameDay[index] += 1
            else:
                repeatedIpScan[index] += 1
            
            daysScan[ip]['timestamp'].add(timestamp)
            daysScan[ip]['scans'] += 1
        else: 
            daysScan[ip] = set()
            daysScan[ip] = {'timestamp': {timestamp}, 'scans': 1}

        if (not(allIps.__contains__(ip))):
            allIps.append(ip)
            uniqueIps[index] += 1

    index +=1
    ipsScanned.append(0)
    uniqueIps.append(0)
    repeatedIpScan.append(0)
    ipScanedAgainOnTheSameDay.append(0)

for ip, data in daysScan.items():
    daysScan[ip]['timestamp'] = sorted(data['timestamp'])

#sort ips by the number os scans
sorted_daysScan = sorted(daysScan.items(), key=lambda x: x[1]['scans'], reverse=True)

with open('../results/temporal_coverage_ips_shodan.txt', 'w') as file:
    file.write("analysing days 2023/11/01 to 2023/11/29 \n\n")
    for i in range(0, len(ipsScanned)-1):
        file.write(f"Day {i+1:<7}: IpsScanned: {ipsScanned[i]:<7} UniqueIps: {uniqueIps[i]:<7} RepeatedIpScan: {repeatedIpScan[i]:<7} IpScanedAgainOnTheSameDay: {ipScanedAgainOnTheSameDay[i]:<7}\n")
    
    file.write("\n")
    for i in sorted_daysScan:
        file.write(str(i))
        file.write("\n")


# TO DO:
# Group information based on: (ip: module:port) so will be possible to differenciate the data collected
# Collect time in the "Timestamp" field to be able to plot CDF over the time between measurements for same IPS
# cdf ips repeated
    # understand about ips verificated just once