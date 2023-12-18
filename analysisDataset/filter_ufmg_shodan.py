import json
import bz2
import argparse
from ipaddress import ip_network


def return_input_parameters():
    parser = argparse.ArgumentParser(description='Inform the month, start and end to be filtered. Pass the input and ouput directory to load data and store results')
    parser.add_argument('month', type=int, help='month to be analized')
    parser.add_argument('startDay', type=int, help='start day to be analized')
    parser.add_argument('endDay', type=int, help='end day to be analized')
    parser.add_argument('inputDirectory', type=int, help='directory with raw shodan data')
    parser.add_argument('outputDirectory', type=int, help='output to store shodan data filtered')
    args = parser.parse_args()
    
    return args

# filter ufmg information in shodan data
# the filter consider that the date os scan is in the filename
def filter_ufmg_shodan(args):
        
    # UFMG ips
    jsonUFMG = []

    # UFMG subnet
    ipUFMG = ip_network('150.164.0.0/16')

    # Shodan scan window
    month = args.month
    startDay = args.startDay
    timespanDays = args.endDay

    inputDirectory = args.inputDirectory
    for d in range(timespanDays):
        day = startDay + d
        filename = f"{inputDirectory}BR.2023{str(month).rjust(2, '0')}{str(day).rjust(2, '0')}.json.bz2"
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
        outputDirectory = args.outputDirectory
        with open(f"{outputDirectory}BR.2023{str(month).rjust(2, '0')}{str(day).rjust(2, '0')}.json", 'w') as f:
            json.dump([jsonUFMG], f, indent=6)

            
    print("done!")

if __name__ == "__main__":
    args = return_input_parameters()
    filter_ufmg_shodan(args)
        


