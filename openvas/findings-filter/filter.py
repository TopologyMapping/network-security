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

    count_results = 0
    for result in results:
        if result.get("id") not in oids:
            continue
        count_results += 1
        new_results.append(result)

    print(f"Filtered {count_results} OIDs from {len(results)}")
    return ET.ElementTree(new_tree)

if __name__ == "__main__":
    with open(sys.argv[1], "r") as fd:
        config = Config.parse_raw(fd.read())

    tree = ET.parse(config.orig_xml_path)
    new_tree = filter(tree, config.nvt_oid_list)
    new_tree.write(config.output_xml_path, encoding="utf8", xml_declaration=True)
