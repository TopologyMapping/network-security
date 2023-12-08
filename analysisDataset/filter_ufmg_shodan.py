import json
import itertools
import bz2

from ipaddress import ip_network

# UFMG ips
jsonUFMG = []

# UFMG subnet
ipUFMG = ip_network('150.164.0.0/16')

# Shodan scan window
month = 11
startDay = 19
timespanDays = 26

for d in range(timespanDays):
    day = startDay + d
    filename = f"../../storage/datasets/survey/downloaded/BR.2023{str(month).rjust(2, '0')}{str(day).rjust(2, '0')}.json.bz2"
    qty = 0

    f = bz2.open(filename, 'rt')

    for line in f:
        singleJson = json.loads(line)

        ip = singleJson.get("ip_str")

        if (ip != None and ip_network(ip).subnet_of(ipUFMG)):
            jsonUFMG.append(singleJson)
            qty += 1
    
    print("Found", qty, "UFMG IPs")

    # Save stuff
    with open(f"../ufmg_ips/BR.2023{str(month).rjust(2, '0')}{str(day).rjust(2, '0')}.json", 'w') as f:
        f.write('[\n')

        for i in range(len(jsonUFMG)):
            json.dump(jsonUFMG[i], f, indent=6)
            if i != len(jsonUFMG) - 1: f.write(',\n')

        f.write('\n]')
        
print("done!")


