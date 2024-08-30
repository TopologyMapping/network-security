import argparse
import bz2
import json
import logging
import os
from argparse import RawTextHelpFormatter
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Optional

from pydantic import BaseModel, Field

CPE_FIELD_IN_SHODAN = "cpe23"
IP_FIELD_IN_SHODAN = "ip_str"
PORT_FIELD_IN_SHODAN = "port"
MODULE_FIELD_IN_SHODAN = "module"
PREFIX_MODULE_FIELD_IN_SHODAN = "_shodan"

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
    product: str = ""
    org: str = ""
    shodan: dict[str, str] = Field(
        ..., alias=PREFIX_MODULE_FIELD_IN_SHODAN
    )  # _ is private atribute in Pydantic, so alias is used to rename field
    port: int

    @classmethod
    def parse_row(cls, scan: dict):
        cpe = (
            [scan["operating_system"]["cpe"]]
            if ("operating_system" in scan) and ("cpe" in scan["operating_system"])
            else []
        )

        location_data = scan.get("location", {})
        location_data["country_name"] = location_data["country"]
        location_data["longitude"] = scan["location"]["coordinates"]["longitude"]
        location_data["latitude"] = scan["location"]["coordinates"]["latitude"]
        location = Location(**location_data) if location_data else None

        operating_system_data = scan.get("operating_system", {}).get("vendor", "")
        operating_system = (
            OperatingSystem(vendor=operating_system_data)
            if operating_system_data
            else None
        )

        autonomous_system_data = scan.get("autonomous_system", {})
        autonomous_system = (
            AutonomousSystem(**autonomous_system_data)
            if autonomous_system_data
            else None
        )

        # handling the different date formats in Censys
        timestampField = scan.get("last_updated_at", "")
        if "." in timestampField:
            # Timestamp with fractional seconds
            timestamp = (
                datetime.strptime(timestampField, "%Y-%m-%dT%H:%M:%S.%fZ")
                .replace(tzinfo=None)
                .isoformat()
            )
        elif "+" in timestampField:
            timestamp = (
                datetime.strptime(timestampField, "%Y-%m-%dT%H:%M:%S.%f%z")
                .replace(tzinfo=None)
                .isoformat()
            )
        else:
            # Timestamp without fractional seconds
            timestamp = (
                datetime.strptime(timestampField, "%Y-%m-%dT%H:%M:%SZ")
                .replace(tzinfo=None)
                .replace(microsecond=1)
                .isoformat()
            )

        dns_data = scan.get("dns", {})
        dns = dns_data if dns_data else {}

        services_data = scan.get("services", {})
        port = services_data.get("port")
        shodan_module = {
            MODULE_FIELD_IN_SHODAN: services_data.get("extended_service_name")
        }

        return Shodan(
            ip_str=scan.get("ip", ""),
            cpe23=cpe,
            location=location,
            operating_system=operating_system,
            autonomous_system=autonomous_system,
            timestamp=timestamp,
            dns=dns,
            product=scan.get("operating_system", {}).get("product", ""),
            org=scan.get("autonomous_system", {}).get("name", ""),
            port=port,
            _shodan=shodan_module,
        )


"""
class to load, filter and make analysis in shodan and censys data
"""


class AnalysisShodanCensysData:
    """
    load_censys_in_shodan_format: parse censys file (.json.bz2) to shodan format (.json)

    input: directory with initial data and output direcoty to store censys file in shodan format

    return: none. Will be stored censys file in shodan format in the path: .../inputDirectory/censys_formated/
    """

    def load_censys_in_shodan_format(
        self, inputDirectoryLoadCensys, outputDirectoryLoadCensys
    ):

        # Ufmg ips directory
        directory = inputDirectoryLoadCensys

        if not (os.path.exists(directory) and os.path.isdir(directory)):
            logging.warning(f"Invalid directory: {directory}")
            raise Exception("Directory not valid or not exists")

        for file in os.scandir(directory):

            # Skip dirs and non-json files
            if (
                not file.is_file()
                or not file.name.endswith(".json.bz2")
                or not file.name.lower().startswith("censys")
            ):
                logging.warning(f"Invalid file: {file.name}. Skipping ...")
                continue

            infoCensysToShodanFormat: list[dict] = []

            # read all scans
            with bz2.open(file, "rt") as f:

                content = f.read()

                scan = json.loads(content)

                for line in scan:

                    for i in line["services"]:
                        line["services"] = i

                        # parse the information using pydantic class
                        infoScanned = Shodan.parse_row(line)

                        infoCensysToShodanFormat.append(
                            infoScanned.model_dump(exclude=None, by_alias=True)
                        )
                        infoScanned = {}  # clean the dict

            # create new filename and ignoring extension .json.bz2
            filenameOutput = (
                file.name.split(".")[0] + ".formated." + file.name.split(".")[1]
            )

            logging.info(f"Creating new folder: {outputDirectoryLoadCensys}")
            os.makedirs(outputDirectoryLoadCensys, exist_ok=True)

            with open(f"{outputDirectoryLoadCensys}{filenameOutput}.json", "w") as file:
                json.dump(infoCensysToShodanFormat, file, indent=6)

    """
        probe_data_shodan_and_censys: analyzes data from shodan and censys (in shodan format) gathering information such as amount of IPS, scanning modules...

        input: directory with initial data and output path to store results

        return: none. Will be stored info about scanning modules, analyzed ips and services provided by the scan in the path: .../outputDirectory/modules_and_ports.json"
    """

    def probe_data_shodan_and_censys(
        self, inputDirectoryProbeData, outputDirectoryProbeData
    ):
        # Ufmg ips directory

        if not (
            os.path.exists(inputDirectoryProbeData)
            and os.path.isdir(inputDirectoryProbeData)
        ):
            logging.warning(f"Invalid directory: {inputDirectoryProbeData}.")
            raise Exception("Directory not valid or not exists")

        # Modules found across all scans, unique ips and services
        modulesShodan: dict[str, set[str]] = {}
        ipsScanned: dict[str, set] = {}
        servicesProvided: list[str] = []
        filenames: list[str] = []

        for file in os.scandir(inputDirectoryProbeData):
            # Skip dirs and non-json files
            if not file.is_file() or not file.path.endswith(".json"):
                logging.warning(f"Invalid file: {file.path}. Skipping ...")
                continue

            # saving names of analyzed files
            filenames.append(file.path.split("/")[-1])

            data = json.load(open(file.path, "r"))

            # Get number of modules and port range
            for scan in data:

                keysDict = scan.keys()
                if not (keysDict) in servicesProvided:
                    servicesProvided.append(keysDict)

                ip = scan["ip_str"]

                if (ip) in ipsScanned:
                    if "cpe23" in scan:
                        cpe = scan["cpe23"]
                        for j in cpe:
                            ipsScanned[ip].add(j)
                else:
                    ipsScanned[ip] = set()
                    if "cpe23" in scan:
                        cpe = scan["cpe23"]
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
            module: {"ports": list(ports), "count": len(ports)}
            for module, ports in modulesShodan.items()
        }

        ips_scanned_serializable = {
            ip: {"cpe": list(cpe)} for ip, cpe in ipsScanned.items()
        }

        data_to_be_dumped = {
            "filesScanned": filenames,
            "modulesShodan": modules_shodan_serializable,
            "uniqueModulesCount": len(modulesShodan),
            "servicesProvided": formatedServicesProvided,
            "uniqueIpsCount": len(ipsScanned),
            "ipsScanned": ips_scanned_serializable,
        }

        # write info collected in a file
        outputPath = f"{outputDirectoryProbeData}/modules_and_ports.json"
        if outputDirectoryProbeData.endswith("/"):
            outputPath = f"{outputDirectoryProbeData}modules_and_ports.json"

        with open(outputPath, "w") as file:
            json.dump(data_to_be_dumped, file, indent=4)

    """
        temporal_scan_ip_shodan_censys: temporal analysis in shodan and censys (in shodan format) data

        input: input directory with initial data and output directory to store results

        return: none. Will be stored info about the IPs analyzed throughout the days in the path: .../outputDirectory/TemporalScan_from_{starting date analyzed}_to_{final date analyzed}.json"
    """

    def temporal_scan_ip_shodan_censys(
        self, inputDirectoryTemporalScan, outputDirectoryTemporalScan
    ):

        # Ufmg ips directory
        if not (
            os.path.exists(inputDirectoryTemporalScan)
            and os.path.isdir(inputDirectoryTemporalScan)
        ):
            logging.info(
                f"The input directory {inputDirectoryTemporalScan} does not exists"
            )
            raise Exception("Directory not valid or does not exists")

        # info to be collected
        daysScan: dict[str, dict] = {}
        uniqueIps: list[int] = [0]
        allIps: list[str] = []
        repeatedIpScan: list[int] = [0]
        ipScanedAgainOnTheSameDay: list[int] = [0]
        ipsScanned: list[int] = [0]
        index = 0

        # read file names first to order and open files in temporal order
        files = [
            file.name
            for file in os.scandir(inputDirectoryTemporalScan)
            if file.is_file() and file.name.endswith(".json")
        ]
        sortedFiles = sorted(files)

        if sortedFiles == []:
            logging.error(
                f"No valid .json files to do temporal analysis in the directory: {inputDirectoryTemporalScan}"
            )
            raise Exception("No valid files in the input directory")

        # reading date by the filename
        # dates are in the end of the filename, before .json
        initialDate = datetime.strptime(sortedFiles[0].split(".")[-2], "%Y%m%d").date()
        finalDate = datetime.strptime(sortedFiles[-1].split(".")[-2], "%Y%m%d").date()

        for file in sortedFiles:

            inputPath = os.path.join(inputDirectoryTemporalScan, file)

            print(inputPath)

            with open(inputPath, 'r') as f:
                for line in f:

                    if not line or line == []:
                        continue

                    # Get number of modules and port range
                    scan = json.loads(line.strip())

                    ip = scan["ip_str"]
                    timestamp = datetime.strptime(
                        scan["timestamp"], "%Y-%m-%dT%H:%M:%S.%f"
                    ).isoformat()

                    ipsScanned[index] += 1

                    if ip in daysScan:

                        if (timestamp) in (daysScan[ip]["timestamp"]):
                            ipScanedAgainOnTheSameDay[index] += 1
                        else:
                            repeatedIpScan[index] += 1

                        daysScan[ip]["timestamp"].add(timestamp)
                        daysScan[ip]["scans"] += 1
                    else:
                        daysScan[ip] = {"timestamp": set(), "scans": 0}

                        daysScan[ip]["timestamp"].add(timestamp)
                        daysScan[ip]["scans"] += 1

                    if ip not in allIps:
                        allIps.append(ip)
                        uniqueIps[index] += 1

            # prepare variables for the next file
            index += 1
            ipsScanned.append(0)
            uniqueIps.append(0)
            repeatedIpScan.append(0)
            ipScanedAgainOnTheSameDay.append(0)

        for ip, data in daysScan.items():
            daysScan[ip]["timestamp"] = sorted(data["timestamp"])

        # sort ips by the number os scans
        sorted_daysScan = sorted(
            daysScan.items(), key=lambda x: x[1]["scans"], reverse=True
        )

        # group data to write json
        data = {
            "days_summary": [
                {
                    "Day": i + 1,
                    "IpsScanned": ipsScanned[i],
                    "UniqueIps": uniqueIps[i],
                    "RepeatedIpScan": repeatedIpScan[i],
                    "IpScanedAgainOnTheSameDay": ipScanedAgainOnTheSameDay[i],
                }
                for i in range(len(ipsScanned) - 1)
            ],
            "sorted_daysScan": sorted_daysScan,
        }

        # format output file name
        outputPath = f"{outputDirectoryTemporalScan}/TemporalScan_from_{initialDate}_to_{finalDate}.json"
        if outputDirectoryTemporalScan.endswith("/"):
            outputPath = f"{outputDirectoryTemporalScan}TemporalScan_from_{initialDate}_to_{finalDate}.json"

        with open(outputPath, "w") as file:
            json.dump(data, file, indent=6)

    """
        filter_ufmg_shodan: filter ufmg information in shodan data. The filter consider that the date of the scan is in the filename

        input: ipUFMG to filter the data, the directory with the initial shodan files and the directory where the results will be saved (filtered shodan files)

        return: none. Will be stored the new shodan files in the path: ...inputDirectory/shodan_UFMG/
    """

    def filter_ufmg_shodan(
        self, inputIpUFMG, inputDirectoryFilterUFMG, outputDirectoryFilterUFMG
    ):

        # UFMG ips
        jsonUFMG = []

        # UFMG subnet
        ipUFMG = ip_network(inputIpUFMG)  # using ip_network to use function subnet_of

        if not (
            os.path.exists(inputDirectoryFilterUFMG)
            and os.path.isdir(inputDirectoryFilterUFMG)
        ):
            logging.error(f"Invalid directory: {inputDirectoryFilterUFMG}.")
            raise Exception("Directory not valid or not exists")

        files = [
            file.name
            for file in os.scandir(inputDirectoryFilterUFMG)
            if file.is_file()
            and file.name.endswith(".json.bz2")
            and file.name.split(".")[1]
        ]
        sorted_files = sorted(files)

        for file in sorted_files:

            if not file.endswith(".json.bz2") or not file.startswith("BR."):
                logging.warning(f"Invalid file: {file}. Skipping ...")
                continue

            #filename = f"{inputDirectoryFilterUFMG}{file}"
            filename = os.path.join(inputDirectoryFilterUFMG, file)

            qty = 0

            f = bz2.open(filename, "rt")

            if f == None:
                logging.warning(f"Invalid file: {filename}. Skipping ...")
                continue

            for line in f:
                singleJson = json.loads(line)

                ip = singleJson.get(IP_FIELD_IN_SHODAN)

                if ip != None and ip_address(ip) in (ipUFMG):
                    jsonUFMG.append(singleJson)
                    qty += 1

            logging.info(f"Found {qty} UFMG IPs in file: {file}")

            # Save stuff and format output path
            filenameOutput = (
                file.split(".")[0] + ".UFMG." + file.split(".")[1]
            )  # ignoring file name extension .json.bz2
            outputPath = os.path.join(outputDirectoryFilterUFMG, filenameOutput)

            logging.info(f"Creating new folder: {outputDirectoryFilterUFMG}")
            os.makedirs(outputDirectoryFilterUFMG, exist_ok=True)

            with open(f"{outputPath}.json", "w") as f:
                json.dump(jsonUFMG, f, indent=6)

            f.close()


def return_input_parameters():
    parser = argparse.ArgumentParser(
        description="""--> Inform the parameters to run all the following functions listed above:

    * Important: Is considered that the Shodan files respect the following name formats "BR.YYYYMMDD.json.bz2" or "BR.YYYYMMDD.json" and the Censys file "CENSYS-UFMG.YYYYMMDD.json.bz2" or "CENSYS-UFMG.YYYYMMDD.json" where YYYY is the year, MM the month and DD the day.

    * Important: Is considered that Censys data are from UFMG.

    Required parameters:
        --directoryShodan = used if will be informed Shodan data
        --directoryCensys = used if will be informed Censys data
        --directoryStoreCensysShodanFormat = used if will be parsed Censys data do Shodan format
        --directoryStoreUFMGShodanData = used if will be filtered the UFMG data in Shodan files
        ipUFMG = UFMG ip to filter input data
        outputDirectory = existing directory to store results and intermediate data

    --> Funcitions that will be executed:
                                                        
    Filter ufmg shodan: 
        Filter UFMG data in shodan file.
    
    Load censys in shodan format: 
        Used if the input file is from Censys -> will be parsed to shodan format
    
    Probe data shodan and censys: 
        Find information about modules, ports and ips from shodan and censys (in shodan format) data.
    
    Temporal scan ip shodan: 
        Make a temporal analysis from shodan and censys (in shodan format) data.
                                     
    """,
        formatter_class=RawTextHelpFormatter,
    )

    parser.add_argument(
        "--directoryShodan",
        dest="directoryShodan",
        action="store",
        metavar="directory-Shodan",
        type=str,
        help="directory with Shodan data",
        required=False,
    )

    parser.add_argument(
        "--directoryStoreUFMGShodanData",
        dest="directoryStoreUFMGShodanData",
        action="store",
        metavar="directory-StoreUFMGShodanData",
        type=str,
        help="inform the directory name that will be created to store UFMG info filtered from Shodan data",
        required=False,
    )

    parser.add_argument(
        "--directoryCensys",
        dest="directoryCensys",
        action="store",
        metavar="directory-censys",
        type=str,
        help="directory with censys data (will be parsed to shodan format)",
        required=False,
    )

    parser.add_argument(
        "--directoryStoreCensysShodanFormat",
        dest="directoryStoreCensysShodanFormat",
        action="store",
        metavar="directory-StoreCensysShodanFormat",
        type=str,
        help="inform the directory name that will be created to store Censys data in Shodan format",
        required=False,
    )

    parser.add_argument(
        "--ipUFMG",
        dest="ipUFMG",
        action="store",
        metavar="ipUFMG",
        type=str,
        help="UFMG ip to filter input data (required if is passed shodan directory)",
        required=False,
    )

    parser.add_argument(
        "--outputDirectory",
        action="store",
        dest="outputDirectory",
        metavar="outputDirectory",
        required=True,
        type=str,
        help="existing directory to store results and intermediate data",
    )

    args = parser.parse_args()

    return args


def censys_analysis(args, analysis):
    if not args.directoryStoreCensysShodanFormat:
        logging.info("It is necessary to inform the directory to store Censys data in Shodan format")
        raise Exception("Missing directoryStoreCensysShodanFormat parameter")

    # will be created a new directory to store censys data formatted --> the following funcionts will read censys data formatted from this directory
    newFolderCensysInShodanFormat = os.path.join(
        args.directoryCensys, args.directoryStoreCensysShodanFormat
    )

    logging.info("Starting function: load_censys_in_shodan_format")
    analysis.load_censys_in_shodan_format(
        args.directoryCensys, newFolderCensysInShodanFormat
    )

    logging.info("Starting function: probe_data_shodan_and_censys")
    analysis.probe_data_shodan_and_censys(newFolderCensysInShodanFormat, args.outputDirectory)

    logging.info("Starting function: temporal_scan_ip_shodan_censys")
    analysis.temporal_scan_ip_shodan_censys(newFolderCensysInShodanFormat, args.outputDirectory)

def shodan_analysis(args, analysis):
    if not args.ipUFMG:
        logging.info("It is necessary to inform ipUFMG to analyze the shodan data")
        raise Exception("Missing ipUFMG parameter")

    if not args.directoryStoreUFMGShodanData:
        logging.info("It is necessary to inform the directory to store UFMG data from Shodan")
        raise Exception("Missing directoryStoreCensysShodanFormat parameter")

    # will be created a new directory to store filtered shodan data --> the following functions will read ufmg shodan data formatted from this directory
    newFolderFilteredShodanUFMG = os.path.join(
        args.directoryShodan, args.directoryStoreUFMGShodanData
    )

    logging.info("Starting function: filter_ufmg_shodan")
    analysis.filter_ufmg_shodan(
        args.ipUFMG, args.directoryShodan, newFolderFilteredShodanUFMG
    )

    logging.info("Starting function: probe_data_shodan_and_censys")
    analysis.probe_data_shodan_and_censys(newFolderFilteredShodanUFMG, args.outputDirectory)

    logging.info("Starting function: temporal_scan_ip_shodan_censys")
    analysis.temporal_scan_ip_shodan_censys(newFolderFilteredShodanUFMG, args.outputDirectory)



if __name__ == "__main__":

    logging.basicConfig(level=logging.DEBUG)

    args = return_input_parameters()

    if not args.outputDirectory:
        logging.info("It is necessary to inform where to store the results")
        raise Exception("Missing outputDirectory parameter")

    analysis: AnalysisShodanCensysData = AnalysisShodanCensysData()

    if args.directoryCensys:

        censys_analysis(args, analysis)

    if args.directoryShodan:

        shodan_analysis(args, analysis)