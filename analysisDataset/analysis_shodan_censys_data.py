import json
import os
from datetime import datetime
import bz2
from ipaddress import ip_network
from pydantic import BaseModel, Field
from typing import Optional
import argparse
from argparse import RawTextHelpFormatter


CPE_FIELD_IN_SHODAN = 'cpe23'
IP_FIELD_IN_SHODAN = 'ip_str'
PORT_FIELD_IN_SHODAN = 'port'
MODULE_FIELD_IN_SHODAN = 'module'
PREFIX_MODULE_FIELD_IN_SHODAN = '_shodan'

class Location(BaseModel):
    city: str
    longitude: float
    latitude: float
    country_code: str
    country_name: str
    continent: str
    province: str

class OperatingSystem(BaseModel):
    vendor: str

class AutonomousSystem(BaseModel):
    name: str
    asn: int
    bgp_prefix: str
    description: str
    country_code: str

class Shodan(BaseModel):
    ip_str: str
    cpe23: list[str] = []
    location: Optional[Location]
    operating_system: Optional[OperatingSystem]
    autonomous_system: Optional[AutonomousSystem]
    timestamp: Optional[str]
    dns: Optional[dict[str, dict[str, list[str]]]]
    product: str = ''
    org: str = ''
    shodan: dict[str, str] = Field(..., alias=PREFIX_MODULE_FIELD_IN_SHODAN) # _ is private atribute in Pydantic, so alias is used to rename field
    port: int

    @classmethod
    def parse_row(cls, scan: dict):
        cpe = [scan["operating_system"]["cpe"]] if ("operating_system" in scan) and ("cpe" in scan["operating_system"]) else []
        
        location_data = scan.get('location', {})
        location_data['country_name'] = location_data['country']
        location_data['longitude'] = scan['location']['coordinates']['longitude']
        location_data['latitude'] = scan['location']['coordinates']['latitude']
        location = Location(**location_data) if location_data else None

        operating_system_data = scan.get('operating_system', {}).get('vendor', '')
        operating_system = OperatingSystem(vendor=operating_system_data) if operating_system_data else None

        autonomous_system_data = scan.get('autonomous_system', {})
        autonomous_system = AutonomousSystem(**autonomous_system_data) if autonomous_system_data else None

        timestamp = scan.get('last_updated_at', '')
        
        dns_data = scan.get('dns', {})
        dns = dns_data if dns_data else {}

        services_data = scan.get('services', {})
        port = services_data.get('port')
        shodan_module = {MODULE_FIELD_IN_SHODAN: services_data.get('extended_service_name')}

        return Shodan(
            ip_str=scan.get('ip', ''),
            cpe23=cpe,
            location=location,
            operating_system=operating_system,
            autonomous_system=autonomous_system,
            timestamp=timestamp,
            dns=dns,
            product=scan.get('operating_system', {}).get('product', ''),
            org=scan.get('autonomous_system', {}).get('name', ''),
            port=port,
            _shodan=shodan_module
        )

def return_input_parameters():
    parser = argparse.ArgumentParser(description='''Inform the parameter of each function to be used.
    Filter ufmg shodan: 
        requires: month, startDay, timespanDays, inputDirectoryFilterUFMG and outputDirectoryFilterUFMG
    
    Load censys in shodan format: 
        requires: inputDirectoryLoadCensys and outputDirectoryLoadCensys
    
    Probe data shodan and censys: 
        requires: inputDirectoryProbeData and outputPathProbeData:
    
    Temporal scan ip shodan: 
        requires: inputDirectoryTemporalScan and outputhPathTemporalScan
    ''', formatter_class=RawTextHelpFormatter)

    parser.add_argument('--month', dest='month', action='store', metavar='month', type=int, help='month to be analized', required=False)
    parser.add_argument('--startDay', dest='startDay', action='store', metavar='startDay', type=int, help='start day to be analized', required=False)
    parser.add_argument('--timespanDays', dest='timespanDays', action='store', metavar='timespanDays', type=int, help='number of days to be analyzed', required=False)
    parser.add_argument('--inputDirectoryFilterUFMG', dest='inputDirectoryFilterUFMG', action='store', metavar='inputDirectoryFilterUFMG', type=str, help='directory with raw shodan data (.json.bz2)', required=False)
    parser.add_argument('--outputDirectoryFilterUFMG', dest='outputDirectoryFilterUFMG', action='store', metavar='outputDirectoryFilterUFMG', type=str, help='output to store UFMG shodan data filtered', required=False)

    parser.add_argument('--inputDirectoryLoadCensys', dest='inputDirectoryLoadCensys', action='store', metavar='inputDirectoryLoadCensys', type=str, help='directory with censys input data (.json) to be parsed in shodan format', required=False)
    parser.add_argument('--outputDirectoryLoadCensys', dest='outputDirectoryLoadCensys', action='store', metavar='outputDirectoryLoadCensys',type=str, help='directory to store censys data in shodan format', required=False)
    
    parser.add_argument('--inputDirectoryProbeData', dest='inputDirectoryProbeData', action='store', metavar='inputDirectoryProbeData', type=str, help='input directory with censys or shodan data (.json) to be analyzed', required=False)
    parser.add_argument('--outputPathProbeData', dest='outputPathProbeData', action='store', metavar='outputPathProbeData',type=str, help='output directory with results', required=False)
    
    parser.add_argument('--inputDirectoryTemporalScan', dest='inputDirectoryTemporalScan', action='store', metavar='inputDirectoryTemporalScan', type=str, help='input directory with censys or shodan data (.json) to be analyzed throughout the days', required=False)
    parser.add_argument('--outputPathTemporalScan', dest='outputPathTemporalScan', action='store', metavar='outputPathTemporalScan',type=str, help='output path with the temporal analysis result', required=False)
    
    args = parser.parse_args()
    
    return args

"""
class to load, filter and make analysis in shodan and censys data
"""
class Analysis_shodan_censys_data:

    def load_censys_in_shodan_format(self, args):
        # Ufmg ips directory
        directory = args.inputDirectoryLoadCensys

        if not (os.path.exists(directory) and os.path.isdir(directory)):
            raise Exception('Directory not valid or not exists')

        #infoCensysToShodanFormat : List[Dict[str, Union[str, Dict[str, str], List[str]]]]= []
        infoCensysToShodanFormat : list[dict] = []

        fileName = ''
        for file in os.scandir(directory):
            fileName, _ = os.path.splitext(file.name)

            # Skip dirs and non-json files
            if (not file.is_file() or not file.path.endswith(".json")):
                continue

            data = json.load(open(file.path, 'r'))

            # read all scans
            for scan in data:

                for i in scan["services"]:
                    #module = i["extended_service_name"]
                    #port = i["port"]

                    scan['services'] = i

                    infoScanned = Shodan.parse_row(scan)

                    infoCensysToShodanFormat.append(infoScanned.model_dump(exclude=None, by_alias=True))
                    infoScanned = {} # clean the dict

        outputDirectory = args.outputDirectoryLoadCensys
        with open(f'{outputDirectory}{fileName}_formated.json', 'w') as file:
            json.dump(infoCensysToShodanFormat, file, indent=6)


    """
        probe_data_shodan_and_censys: analyzes data from shodan and censys (in shodan format) gathering information such as amount of IPS, scanning modules...

        input: directory with initial data and output path to store results

        return: info about scanning modules, analyzed ips and services provided by the scan
    """
    def probe_data_shodan_and_censys (self, args): 
        # Ufmg ips directory
        directory : str = args.inputDirectoryProbeData

        if not (os.path.exists(directory) and os.path.isdir(directory)):
            raise Exception('Directory not valid or not exists')

        # Modules found across all scans, unique ips and services
        modulesShodan : dict[str, set[str]] = {}
        ipsScanned : dict[str, set] = {}
        servicesProvided : list[str] = []

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
        servicesProvided = [(keysDict) for keysDict in servicesProvided]

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
        path_output_file = args.outputPathProbeData
        with open(path_output_file, 'w') as file:
            json.dump(data_to_be_dumped, file, indent=4)

    
    """
        temporal_scan_ip_shodan: temporal analysis in shodan and censys (in shodan format) data

        input: directory with initial data and outputPath to store results

        return: info about the IPs analyzed throughout the days
    """    
    def temporal_scan_ip_shodan(self, args):
        # Ufmg ips directory
        directory = args.inputDirectoryTemporalScan

        if not (os.path.exists(directory) and os.path.isdir(directory)):
            raise Exception('Directory not valid or not exists')

        # info to be collected
        daysScan : dict[str, dict] = {}
        uniqueIps : list[int] = [0]
        allIps : list[str] = []
        repeatedIpScan: list[int] = [0]
        ipScanedAgainOnTheSameDay : list[int]= [0]
        ipsScanned : list[int]= [0]
        index = 0

        # read file names first to order and open files in temporal order
        files = [file.name for file in os.scandir(directory) if file.is_file() and file.name.endswith(".json") and file.name.split('.')[1] ]
        sorted_files = sorted(files)

        for file in sorted_files:

            data = json.load(open(f"{directory}{file}", 'r'))

            # Get number of modules and port range
            for scan in data:      
                ip = scan["ip_str"]
                timestamp = datetime.strptime(scan['timestamp'], "%Y-%m-%dT%H:%M:%S.%f").isoformat()

                ipsScanned[index] += 1

                if ip in daysScan:
                    
                    if ((timestamp) in (daysScan[ip]['timestamp'])):
                        ipScanedAgainOnTheSameDay[index] += 1
                    else:
                        repeatedIpScan[index] += 1
                    
                    daysScan[ip]['timestamp'].add(timestamp)
                    daysScan[ip]['scans'] += 1
                else: 
                    daysScan[ip] = {'timestamp': set(), 'scans': 0}

                    daysScan[ip]['timestamp'].add(timestamp)
                    daysScan[ip]['scans'] += 1

                if (not((ip) in allIps)):
                    allIps.append(ip)
                    uniqueIps[index] += 1

            # prepare variables for the next file
            index +=1
            ipsScanned.append(0)
            uniqueIps.append(0)
            repeatedIpScan.append(0)
            ipScanedAgainOnTheSameDay.append(0)

            break

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
        path_output_file = args.outputPathTemporalScan
        with open(path_output_file, 'w') as file:
            json.dump(data, file, indent=6)

    

    # filter ufmg information in shodan data
    # the filter consider that the date os scan is in the filename
    """
        filter_ufmg_shodan: filter ufmg information in shodan and censys (in shodan format) data. The filter consider that the date os scan is in the filename

        input: month, start day and timespan days to make the filter, the input directory with initial data and output directory

        return: json file with shodan/censys data with UFMG information
    """
    def filter_ufmg_shodan(self, args):
            
        IP_FIELD_IN_SHODAN="ip_str"
        # UFMG ips
        jsonUFMG = []

        # UFMG subnet
        ipUFMG = ip_network('150.164.0.0/16')

        # Shodan scan window
        month = args.month
        startDay = args.startDay
        timespanDays = args.timespanDays

        inputDirectory = args.inputDirectoryFilterUFMG
        for d in range(timespanDays):
            day = startDay + d
            filename = f"{inputDirectory}BR.2023{str(month).rjust(2, '0')}{str(day).rjust(2, '0')}.json.bz2"
            qty = 0

            f = bz2.open(filename, 'rt')

            for line in f:
                singleJson = json.loads(line)

                ip = singleJson.get(IP_FIELD_IN_SHODAN)

                if (ip != None and ip_network(ip).subnet_of(ipUFMG)): # type: ignore
                    jsonUFMG.append(singleJson)
                    qty += 1
            
            print(f"Found {qty} UFMG IPs")

            # Save stuff
            outputDirectory = args.outputDirectoryFilterUFMG
            with open(f"{outputDirectory}BR.2023{str(month).rjust(2, '0')}{str(day).rjust(2, '0')}.json", 'w') as f:
                json.dump([jsonUFMG], f, indent=6)

if __name__ == "__main__":
    args = return_input_parameters()

    analysis: Analysis_shodan_censys_data =  Analysis_shodan_censys_data()
    
    if (args.month and args.startDay and args.timespanDays and args.inputDirectoryFilterUFMG and args.outputDirectoryFilterUFMG):
        analysis.filter_ufmg_shodan
    
    if (args.inputDirectoryLoadCensys and args.outputDirectoryLoadCensys):
        analysis.load_censys_in_shodan_format(args)
    
    if (args.inputDirectoryProbeData and args.outputPathProbeData):
        analysis.probe_data_shodan_and_censys(args)
    
    if (args.inputDirectoryTemporalScan and args.outputPathTemporalScan):
        analysis.probe_data_shodan_and_censys(args)

        
