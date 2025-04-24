#!/usr/bin/env python3

import dataclasses
import pathlib
import sys
import xml.etree.ElementTree as ET

import dataclasses_json
from yacryptopan import CryptoPAn


@dataclasses_json.dataclass_json
@dataclasses.dataclass
class Config:
    orig_xml_path: pathlib.Path
    output_xml_path: pathlib.Path
    nvt_oid_list: list[str]
    hostname_map: dict[str, str]
    cryptopan_key: str


def filter_anonymize(
    tree: ET,
    oids: list[str],
    hostname_map: dict[str, str],
    cpan: CryptoPAn,
) -> ET.ElementTree:
    """Filter NVTs by OID and anonymize in place"""

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

    count_results = 0
    for result in results:
        if result.get("id") not in oids:
            continue
        count_results += 1

        host_elem = result.find("host")
        desc_elem = result.find("description")
        desc_text = desc_elem.text if desc_elem.text is not None else ""

        if (host_ip := host_elem.text) is not None:
            crypted_ip = cpan.anonymize(host_ip)
            host_elem.text = crypted_ip
            print(f"{host_ip} -> {crypted_ip}")
            desc_text = desc_text.replace(host_ip, crypted_ip)

        host_name_elem = host_elem.find("hostname")
        if host_name_elem is None:
            continue
        host_name_text = host_name_elem.text
        if (host_name_anon := hostname_map.get(host_name_text)) is not None:
            print(f"{host_name_text} -> {host_name_anon}")
            host_name_elem.text = host_name_anon
            desc_text = desc_text.replace(host_name_text, host_name_anon)
        desc_elem.text = desc_text

        new_results.append(result)

    print(f"Filtered {count_results} OIDs from {len(results)}")
    return ET.ElementTree(new_tree)

if __name__ == "__main__":
    with open(sys.argv[1], "r") as fd:
        config = Config.from_json(fd.read())

    if len(config.cryptopan_key) != 32:
        raise ValueError("CryptoPAn key must have 32 bytes")
    cpan = CryptoPAn(bytes(config.cryptopan_key, encoding="ascii"))

    tree = ET.parse(config.orig_xml_path)
    new_tree = filter_anonymize(tree, config.nvt_oid_list, config.hostname_map, cpan)
    new_tree.write(config.output_xml_path, encoding="utf8", xml_declaration=True)