#!/usr/bin/env python3

import argparse
import logging
import os
import pathlib
import random
import string
import sys
import xml.etree.ElementTree as ET

from yacryptopan import CryptoPAn

import anonymizer


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Anonymize hostnames")
    parser.add_argument(
        "--keep-cctld",
        action="store_true",
        default=False,
        help="Keep country-code TLDs in anonymized hostnames [%(default)s]",
    )
    parser.add_argument(
        "--immediate-cctld",
        action="store_true",
        default=False,
        help="Assume domain names do not have generic TLDs like .com or .org [%(default)s]",
    )
    parser.add_argument(
        "--tlds-file",
        metavar="JSON",
        type=pathlib.Path,
        default="data/tlds.json",
        help="Path to the TLDs JSON file [%(default)s]",
    )
    parser.add_argument(
        "--special-cctlds-file",
        metavar="FILE",
        type=pathlib.Path,
        default="data/special-cctlds-list.txt",
        help="Path to the special ccTLDs list file [%(default)s]",
    )
    parser.add_argument(
        "--dns-keywords-file",
        metavar="FILE",
        type=pathlib.Path,
        default="data/dns-keywords.txt",
        help="Path to the DNS keywords list file [%(default)s]",
    )
    parser.add_argument(
        "--output-path",
        metavar="DIR",
        type=pathlib.Path,
        default="anon-output",
        help="Path to the anonymized report XML [%(default)s]",
    )
    parser.add_argument(
        "reports",
        nargs="+",
        type=pathlib.Path,
        help="OpenVAS reports in XML format",
    )
    return parser


def anonymize(
    tree: ET,
    cpan: CryptoPAn,
    azer: anonymizer.HostnameAnonymizer,
) -> ET.ElementTree:
    root = tree.getroot()
    if "report" not in root.tag:
        print("This does not seem to be a valid Greenbone OpenVAS XML file.")
        sys.exit(1)

    outer_report = root.find("report")
    inner_report = outer_report.find("report")
    report = outer_report if inner_report is None else inner_report
    results = report.find("results")

    new_tree = ET.Element("report", attrib={"id": "gtcrivo"})
    internal_report = ET.SubElement(new_tree, "report")
    new_results = ET.SubElement(internal_report, "results")

    for result in results:
        host_elem = result.find("host")
        desc_elem = result.find("description")
        desc_text = desc_elem.text if desc_elem.text is not None else ""

        if (host_ip := host_elem.text) is not None:
            crypted_ip = cpan.anonymize(host_ip)
            host_elem.text = crypted_ip
            logging.debug(f"{host_ip} -> {crypted_ip}")
            desc_text = desc_text.replace(host_ip, crypted_ip)

        host_name_elem = host_elem.find("hostname")
        if host_name_elem is not None:
            host_name_text = host_name_elem.text
            if (host_name_anon := azer.anonymize_hostname(host_name_text)) is not None:
                logging.info(f"{host_name_text} -> {host_name_anon}")
                host_name_elem.text = host_name_anon
                desc_text = desc_text.replace(host_name_text, host_name_anon)
            desc_elem.text = desc_text

        new_results.append(result)

    for host in report.findall("host"):
        ip = host.find("ip")
        logging.info(f"Processing host: {ip.text}")
        ip.text = cpan.anonymize(ip.text)
        internal_report.append(host)

    return ET.ElementTree(new_tree)


if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    cryptopan_key = "".join(
        random.choices(string.ascii_letters + string.digits + string.punctuation, k=32)
    )
    cryptopan_key = bytes(cryptopan_key, encoding="ascii")
    assert len(cryptopan_key) == 32
    cpan = CryptoPAn(cryptopan_key)

    azer = anonymizer.HostnameAnonymizer(
        tlds_path=args.tlds_file,
        special_cctlds_path=args.special_cctlds_file,
        dns_keywords_path=args.dns_keywords_file,
        keep_cctld=args.keep_cctld,
        immediate_cctld=args.immediate_cctld,
    )

    os.makedirs(args.output_path, exist_ok=True)
    for reportfp in args.reports:
        tree = ET.parse(reportfp)
        new_tree = anonymize(tree, cpan, azer)
        new_tree.write(args.output_path / reportfp.name, encoding="utf8", xml_declaration=True)
