#!/usr/bin/env python3

import dataclasses
import pathlib
import sys
import xml.etree.ElementTree as ET

from pydantic import BaseModel


DETAIL_OS_NAMES = ["OS-Detection", "OS", "best_os_cpe"]


class Config(BaseModel):
    orig_xml_path: pathlib.Path
    output_xml_path: pathlib.Path
    nvt_oid_list_path: pathlib.Path

    class Config:
        arbitrary_types_allowed = True


def filter(
    tree: ET,
    oids: list[str],
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

    filtered_oid_hosts = set()
    for result in results:
        if result.get("id") not in oids:
            continue
        host_elem = result.find("host")
        if (host_ip := host_elem.text) is not None:
            filtered_oid_hosts.add(host_ip)
        new_results.append(result)
    print(f"Filtered {len(new_results)} OIDs from {len(results)}, {len(filtered_oid_hosts)} hosts")

    found_hosts = set()
    ndetails = 0
    for host in report.findall("host"):
        ip = host.find("ip").text
        if ip not in filtered_oid_hosts:
            continue
        new_host = None
        for detail in host.findall("detail"):
            name = detail.find("name")
            if name is None or name.text not in DETAIL_OS_NAMES:
                continue
            if new_host is None:
                found_hosts.add(ip)
                new_host = ET.SubElement(internal_report, "host")
                new_ip = ET.SubElement(new_host, "ip")
                new_ip.text = ip
            new_host.append(detail)
            ndetails += 1
    print(f"Added {len(found_hosts)} hosts with a total of {ndetails} OS detection details")

    return ET.ElementTree(new_tree)


if __name__ == "__main__":
    with open(sys.argv[1], "r") as fd:
        config = Config.parse_raw(fd.read())

    with open(config.nvt_oid_list_path.expanduser(), "r") as fd:
        nvt_oid_list = [line.strip() for line in fd if line.strip()]

    tree = ET.parse(config.orig_xml_path.expanduser())
    new_tree = filter(tree, nvt_oid_list)
    new_tree.write(config.output_xml_path.expanduser(), encoding="utf8", xml_declaration=True)
