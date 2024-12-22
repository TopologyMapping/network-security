"""
Focus: Classificate scanners tests by categories:
    - What is detected: for example, which CVEs are checked
    - How is detected: for example, with an exploit, with version check, with an authenticated scan ...

Steps:
Run over all vulns tests
->
Check if there is CVE
-> 
    If CVE exists: tries to classificate in categories HOW is detected
    
    otherwise: tries to check if is the same problem comparing textual information
        if similar texts: classificate in categories

Use dicts for each tool to store the CVEs checked -> will store info about classification
Store all codes without CVE and tries to match them : Brute Force ? Compare by title similarites ?

"""

import json
import argparse
from metasploit import analysis_metasploit_modules
from openvas import analysis_openvas_NVTS
from nuclei import analysis_nuclei_templates
from nmap import analysis_nmap_scripts


def receive_arguments():
    parser = argparse.ArgumentParser(
        description="Match CVEs between Nmap, OpenVAS, and Nuclei templates."
    )
    parser.add_argument("--nmap", required=False, help="Path to the Nmap directory.")
    parser.add_argument(
        "--openvas", required=False, help="Path to the OpenVAS directory."
    )
    parser.add_argument(
        "--nuclei", required=False, help="Path to the Nuclei templates directory."
    )
    parser.add_argument(
        "--metasploit",
        required=False,
        help="Path to the metasploit templates directory.",
    )
    parser.add_argument(
        "--initialRange", type=int, required=True, help="Initial classification range."
    )
    parser.add_argument(
        "--finalRange", type=int, required=True, help="Final classification range."
    )
    parser.add_argument("--output", required=True, help="Output JSON file.")
    parser.add_argument("--ip_port", required=True, help="LLM ip and port.")

    return parser.parse_args()


def classification(args) -> dict:
    """
    This function receives the arguments from the user and classifies the scripts for each tool. The output is divided between the files with CVEs and the files without CVEs. All results are grouped in a dictionary.
    """

    tests_with_no_CVE: list = []
    results: dict = {}

    if args.nmap:
        nmap_info, scripts_with_no_CVE = analysis_nmap_scripts(
            args.nmap, args.initialRange, args.finalRange, args.ip_port
        )

        results["nmap"] = nmap_info
        tests_with_no_CVE += scripts_with_no_CVE

    if args.metasploit:
        metasploit_info, modules_with_no_CVE = analysis_metasploit_modules(
            args.metasploit, args.initialRange, args.finalRange, args.ip_port
        )

        results["metasploit"] = metasploit_info
        tests_with_no_CVE += modules_with_no_CVE

    if args.nuclei:
        nuclei_info, templates_with_no_CVE = analysis_nuclei_templates(
            args.nuclei, args.initialRange, args.finalRange, args.ip_port
        )

        results["nuclei"] = nuclei_info
        tests_with_no_CVE += templates_with_no_CVE

    if args.openvas:
        openvas_info, NVTS_with_no_CVE = analysis_openvas_NVTS(
            args.openvas, args.initialRange, args.finalRange, args.ip_port
        )

        results["openvas"] = openvas_info
        tests_with_no_CVE += NVTS_with_no_CVE

    results["tests_with_no_CVE"] = tests_with_no_CVE

    return results


if __name__ == "__main__":

    args = receive_arguments()

    results = classification(args)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=4)
