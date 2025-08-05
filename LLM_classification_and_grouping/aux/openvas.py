"""
This module provides functionality for classifying Openvas scripts.

The classification process involves:
1. Analyzing the content of each script and extracting metadata using regular expressions.
2. Sending the extracted information to a language model (LLM) with a specific prompt for classification.
3. Organizing the scripts into appropriate categories based on the LLM's responses.

The classification is performed in batches to efficiently handle large numbers of files.
"""

import dataclasses
import json
import os
import re
import time
from collections import defaultdict
from difflib import SequenceMatcher
from typing import Any

from dataclasses_json import dataclass_json

from .constants import (
    PROMPT_OPENVAS_AUTHENTICATED,
    PROMPT_OPENVAS_EXPLOIT,
    PROMPT_OPENVAS_NOT_EXPLOIT_NOT_AUTHENTICATED,
)
from .llm import LLMHandler
from .utils import ScriptClassificationResult, read_file_with_fallback

RESULTS_DIRECTORY_NAME = "./results"


# defining the dataclasses to store information
@dataclass_json
@dataclasses.dataclass
class OpenvasNVTInfo:
    file: str
    cves: list[str]
    id: str
    classification: str
    qod_info: tuple[str, int]


@dataclass_json
@dataclasses.dataclass
class OpenvasSimilarityResults:
    number_skipped_files: int
    number_main_files: int
    number_similar_files: int
    number_maybe_similar_files: int
    categories_in_main_files: int
    main_files: dict
    similars: dict
    maybe_similars: dict
    NVTS_with_no_CVE: list


@dataclass_json
@dataclasses.dataclass(frozen=True)
class CveQodKey:
    cves: tuple[str, ...]
    qod_type: str  # the qod_type is present on the dict QOD_TYPE_AND_VALUE below


# qod values for OpenVAS - https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html#quality-of-detection-concept
QOD_TYPE_AND_VALUE = {
    "exploit": 100,
    "remote_vul": 99,
    "remote_app": 98,
    "package": 97,
    "registry": 97,
    "remote_active": 95,
    "remote_banner": 80,
    "executable_version": 80,
    "default": 75,
    "remote_analysis": 70,
    "remote_probe": 50,
    "remote_banner_unreliable": 30,
    "executable_version_unreliable": 30,
    "general_note": 1,
    "timeout": 0,
}

INVERSE_QOD_TYPE_AND_VALUE = {value: key for key, value in QOD_TYPE_AND_VALUE.items()}

FILE_EXTENSION_OPENVAS = ".nasl"

# these values are arbitrary and can be changed if necessary
SCORE_SIMILAR_FILE = 31
SCORE_MAYBE_SIMILAR_FILE = 16

CVE_REGEX = re.compile(r'script_cve_id\("(?P<cve1>[^"]+)"(?:,\s*"(?P<cve2>[^"]+)")*\);')
DEPRECATED_REGEX = re.compile(
    r'script_tag\(name:"(?P<name>deprecated)",\s*value:(?P<value>TRUE)\);'
)
QOD_REGEX = re.compile(
    r'script_tag\(name:"(?P<qod_type>qod|qod_type)",\s*value:"(?P<qod_value>[^"]+)"\);'
)
OID_REGEX = re.compile(r'script_oid\("(?P<oid>[\d.]+)"\)')
SOLUTION_TYPE_REGEX = re.compile(
    r'script_tag\(name:"(?P<name>solution_type)",\s*value:"(?P<value>[^"]+)"\);'
)
INSIGHT_REGEX = re.compile(
    r'script_tag\(name:"(?P<name>insight)",\s*value:"(?P<value>[^"]+)"\);'
)
IMPACT_REGEX = re.compile(
    r'script_tag\(name:"(?P<name>impact)",\s*value:"(?P<value>[^"]+)"\);'
)
SOLUTION_REGEX = re.compile(
    r'script_tag\(name:"(?P<name>solution)",\s*value:"(?P<value>[^"]+)"\);'
)
SUMMARY_REGEX = re.compile(
    r'script_tag\(name:"(?P<name>summary)",\s*value:"(?P<value>[^"]+)"\);'
)
VULDETECT_REGEX = re.compile(
    r'script_tag\(name:"(?P<name>vuldetect)",\s*value:"(?P<value>[^"]+)"\);'
)
AFFECTED_REGEX = re.compile(
    r'script_tag\(name:"(?P<name>affected)",\s*value:"(?P<value>[^"]+)"\);'
)


# Functions to extract information
def extract_cve_from_openvas(content: str) -> list[str]:
    cves = CVE_REGEX.findall(content)
    cves_to_list = [cve for match in cves for cve in match if cve]
    return cves_to_list


def is_openvas_file_deprecated(file_content) -> bool:
    match = DEPRECATED_REGEX.search(file_content)
    return bool(match) if match else False


def extract_qod_openvas(content: str) -> tuple[str, int]:
    qod_match = QOD_REGEX.search(content)
    if not qod_match:
        return ("", -1)

    qod_type = ""
    qod_value = -1

    if qod_match.group("qod_value").isdigit():
        qod_value = int(qod_match.group("qod_value"))
        qod_type = (
            INVERSE_QOD_TYPE_AND_VALUE[qod_value]
            if qod_value in INVERSE_QOD_TYPE_AND_VALUE
            else ""
        )
    else:
        qod_type = qod_match.group("qod_value")
        qod_value = (
            QOD_TYPE_AND_VALUE[qod_type] if qod_type in QOD_TYPE_AND_VALUE else -1
        )

    if qod_value == "":
        return ("", -1)

    return qod_type if qod_type else "", qod_value if qod_value else -1


def extract_oid_openvas(content: str) -> str:
    match = OID_REGEX.search(content)
    return match.group("oid") if match else ""


def extract_solution_type_openvas(content: str) -> str:
    solution_type = SOLUTION_TYPE_REGEX.search(content)
    return solution_type.group("value").replace("\n", "") if solution_type else ""


def extract_insight_openvas(content: str) -> str:
    insight = INSIGHT_REGEX.search(content)
    return insight.group("value").replace("\n", "") if insight else ""


def extract_impact_openvas(content: str) -> str:
    impact = IMPACT_REGEX.search(content)
    return impact.group("value").replace("\n", "") if impact else ""


def extract_solution_openvas(content: str) -> str:
    solution = SOLUTION_REGEX.search(content)
    return solution.group("value").replace("\n", "") if solution else ""


def extract_summary_openvas(content: str) -> str:
    description = SUMMARY_REGEX.search(content)
    return description.group("value").replace("\n", "") if description else ""


def extract_vuldetect_openvas(content: str) -> str:
    vuldetect = VULDETECT_REGEX.search(content)
    return vuldetect.group("value").replace("\n", "") if vuldetect else ""


def extract_affected_openvas(content: str) -> str:
    affected = AFFECTED_REGEX.search(content)
    return affected.group("value").replace("\n", "") if affected else ""


def classification_openvas(content: str, qod_value: int, qod_type: str, llm) -> str:
    """
    This function filters the content of the Openvas script and classifies it according to the QOD value and type.
    """
    classification: str = ""

    qod_authenticated_scan = QOD_TYPE_AND_VALUE[
        "package"
    ]  # QOD_VALUE['registry'] is also a authenticated scan

    if (
        qod_value >= QOD_TYPE_AND_VALUE["remote_app"]
        or qod_value == QOD_TYPE_AND_VALUE["remote_active"]
    ):
        classification = llm.classification_text_generation(
            content, PROMPT_OPENVAS_EXPLOIT
        )
    elif qod_value == qod_authenticated_scan or qod_type == "executable_version":
        classification = llm.classification_text_generation(
            content, PROMPT_OPENVAS_AUTHENTICATED
        )
    else:
        classification = llm.classification_text_generation(
            content, PROMPT_OPENVAS_NOT_EXPLOIT_NOT_AUTHENTICATED
        )

    return classification


def analysis_openvas_NVTS(
    openvas_folder: str, initial_range: int, final_range: int, ip_port: str
) -> ScriptClassificationResult:
    """
    How the function works:
        This file handles the classification of Openvas scripts. Useful information is taken from the file metadata to perform the classification, and then sent to the LLM that will perform the task.

        Since there are many files to be classified, the function operates in batches, classifying files in a given range of values.

    Input: Folder with Openvas NVTS and range for classification.

    Output: classified files and information about files without CVE.

    *Classification is not performed on all Openvas files. Check the 'get_list_unique_files' function.
    """

    llm = LLMHandler(ip_port)

    NVTS_with_no_CVE: list[str] = []

    openvas_info: list[dict] = []

    openvas_files: list[str] = get_list_unique_files(openvas_folder)

    i = 0
    for openvas_file in openvas_files[initial_range:final_range]:

        i+=1
        print ("Arquivo atual:", i)
        openvas_file = os.path.abspath(openvas_file)

        content = read_file_with_fallback(openvas_file)

        if not content:
            continue

        if is_openvas_file_deprecated(content):
            continue

        qod_info: tuple[str, int] = extract_qod_openvas(content)

        if not qod_info:
            continue

        qod_type: str = qod_info[0]
        qod_value: int = qod_info[1]

        cves : list[str] = extract_cve_from_openvas(content)

        if not cves:

            NVTS_with_no_CVE.append(openvas_file)

        oid : str = extract_oid_openvas(content)

        start_time = time.time()

        classification : str = classification_openvas(content, qod_value, qod_type, llm)

        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Elapsed time: {elapsed_time:.2f} seconds")

        info = OpenvasNVTInfo(
            file=openvas_file,
            cves=cves,
            id=oid,
            classification=classification,
            qod_info=qod_info,
        ).to_dict()

        openvas_info.append(info)

    return ScriptClassificationResult(
        scripts_with_cves=openvas_info, scripts_without_cves=NVTS_with_no_CVE
    )


def similarity_text(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def get_file_info(content: str) -> dict[str, Any]:
    file_affected: str = extract_affected_openvas(content)
    file_summary: str = extract_summary_openvas(content)
    file_vuldetect: str = extract_vuldetect_openvas(content)
    file_solution: str = extract_solution_openvas(content)
    file_insight: str = extract_insight_openvas(content)
    file_impact: str = extract_impact_openvas(content)
    file_vuldetect: str = extract_vuldetect_openvas(content)
    file_qod_info: tuple[str, int] = extract_qod_openvas(content)

    result = {
        "affected": file_affected,
        "summary": file_summary,
        "vuldetect": file_vuldetect,
        "solution": file_solution,
        "insight": file_insight,
        "impact": file_impact,
        "qod": file_qod_info,
    }

    return result


def return_similarity_score(
    new_file_name: str, new_file_info: dict[str, Any], old_file_name: str, old_file_info: dict[str, Any]
) -> int:
    """
    This function returns a score based on the similarity of the files, involving metadada information.
    This is important to group similar files and avoid unnecessary classification, read the 'compare_similarity_openvas' function for more information.
    """

    score = 0
    if new_file_info["qod"] == old_file_info["qod"]:
        score += 11
    if similarity_text(new_file_info["affected"], old_file_info["affected"]) > 0.9:
        score += 11
    if new_file_info["summary"] == old_file_info["summary"]:
        score += 8
    if similarity_text(new_file_name, old_file_name) > 0.9:
        score += 8
    if new_file_info["insight"] == old_file_info["insight"]:
        score += 5
    if new_file_info["vuldetect"] == old_file_info["vuldetect"]:
        score += 3
    if new_file_info["solution"] == old_file_info["solution"]:
        score += 2
    if new_file_info["impact"] == old_file_info["impact"]:
        score += 1

    return score


def get_list_unique_files(openvas_folder: str) -> list[str]:

    openvas_checked_files: dict = compare_similarity_openvas(openvas_folder)

    list_unique_files = []
    for value in openvas_checked_files["main_files"].values():
        list_unique_files += value

    print("Processing files", len(list_unique_files))
    return list_unique_files


def check_active_script(
    qod_value: int, key: CveQodKey, openvas_qod_cve: dict[CveQodKey, list[str]], openvas_file: str
) -> bool:
    """
    Function to check if a script performs actives checks or not.
    If so, it is important to separate it from the others.
    """

    if (
        qod_value >= QOD_TYPE_AND_VALUE["remote_app"]
        or qod_value == QOD_TYPE_AND_VALUE["remote_active"]
    ):

        # using a new key to separate the active codes
        active_key = CveQodKey(cves=key.cves, qod_type=f"{key.qod_type} active")

        if active_key not in openvas_qod_cve:
            openvas_qod_cve[active_key] = []

        openvas_qod_cve[active_key].append(openvas_file)

        return True

    return False


def verifies_similarity(
    score: int,
    key: CveQodKey,
    similars: dict[CveQodKey, list[str]],
    maybe_similars: dict[CveQodKey, list[str]],
    openvas_file: str,
) -> bool:
    """
    This functions verifies if the analyzed file is similar to another file. Based on the score received, it classifies the file as similar or maybe similar to the initial file.
    """

    similar: bool = False

    code_is_similar: bool = score >= SCORE_SIMILAR_FILE
    code_is_maybe_similar: bool = score >= SCORE_MAYBE_SIMILAR_FILE

    if code_is_similar:
        similar = True

        if key not in similars:
            similars[key] = []
            similars[key].append(openvas_file)
        else:
            similars[key].append(openvas_file)

    elif code_is_maybe_similar:
        similar = True

        if key not in maybe_similars:
            maybe_similars[key] = []
            maybe_similars[key].append(openvas_file)
        else:
            maybe_similars[key].append(openvas_file)

    return similar


def compare_similarity_openvas(openvas_folder: str) -> dict:
    """
    How the function works:
        When classifying scripts, since Openvas has almost 100 thousand files, it is important to group similar files to avoid computational costs.

        Grouping is done by deterministically checking file data, such as metadata, script name and QOD. The more common characteristics, the more confidence in the similarity. It is worth noting that not all common characteristics have the same weight, which were determined by script analysis and grouping tests. These values are not absolute and can be changed if necessary.

        Files are classified into 3 groups:

        - Main files = Files with unique characteristics for each set of CVE + QOD

        - Similar = Files that have a high chance of being similar to files marked as main, sharing several characteristics.

        - Maybe similar = Files that have fewer characteristics in common, but that are probably similar.

        The control for similarity classification can be done by changing the SCORE constants at the beginning of the file, which restrict or facilitate the requirements for grouping.

    Input: Folder with openvas files
    Output: Dictionary with the set of unique, similar, maybe similar and files without CVE.

    * This script also saves the results in a folder 'results' in the file 'info_similarity_NVTS_openvas.json' in the current directory.
    """

    openvas_files: list[str] = [
        os.path.join(root, file)
        for root, _, files in os.walk(openvas_folder)
        for file in files
        if file.endswith(FILE_EXTENSION_OPENVAS)
    ]

    openvas_qod_cve: dict[CveQodKey, list[str]] = defaultdict(list)
    similars: dict[CveQodKey, list[str]] = {}
    maybe_similars: dict[CveQodKey, list[str]] = {}

    files_skipped: list[str] = []

    NVTS_with_no_CVE: list[str] = []

    print("Total files ", len(openvas_files))
    for openvas_file in openvas_files:

        new_file_name = os.path.basename(openvas_file)

        content = read_file_with_fallback(openvas_file)

        if not content:
            continue

        if is_openvas_file_deprecated(content):
            files_skipped.append(openvas_file)
            continue

        new_file_info : dict[str, Any] = get_file_info(content)

        if not new_file_info["qod"]:
            files_skipped.append(openvas_file)
            continue

        cves: list[str] = extract_cve_from_openvas(content)

        if not (cves):

            NVTS_with_no_CVE.append(openvas_file)

        qod_type: str = new_file_info["qod"][0]
        qod_value: int = new_file_info["qod"][1]

        # the dict key is the cve checked and the qod
        # with this is possible to separate codes that verifies the same CVE
        sorted_cves = tuple(
            sorted(cves)
        )  # Ensure the CVEs are sorted and converted to a tuple
        key = CveQodKey(cves=sorted_cves, qod_type=qod_type)

        # Use the tuple as a key in your dictionary
        if key not in openvas_qod_cve:
            openvas_qod_cve[key].append(openvas_file)
            continue

        is_active_code : bool = check_active_script(
            qod_value, key, openvas_qod_cve, openvas_file
        )

        if is_active_code:
            continue

        is_similar : bool = False

        for old_file in openvas_qod_cve[key]:

            old_file_content = read_file_with_fallback(old_file)

            if not old_file_content:
                continue

            old_file_info : dict[str, Any] = get_file_info(old_file_content)

            old_file_name : str = os.path.basename(old_file)

            score : int = return_similarity_score(
                new_file_name, new_file_info, old_file_name, old_file_info
            )

            is_similar : bool = verifies_similarity(
                score, key, similars, maybe_similars, openvas_file
            )

            if is_similar:
                break

        if is_similar is False:
            openvas_qod_cve[key].append(openvas_file)

    openvas_qod_cve_serializable = {
        key.to_json(): value for key, value in openvas_qod_cve.items()
    }

    similars_serializable = {key.to_json(): value for key, value in similars.items()}

    maybe_similars_serializable = {
        key.to_json(): value for key, value in maybe_similars.items()
    }

    results: dict = {
        "number_skipped_files": len(files_skipped),
        "number_main_files": sum(len(value) for value in openvas_qod_cve.values()),
        "number_similar_files": sum(len(value) for value in similars.values()),
        "number_maybe_similar_files": sum(
            len(value) for value in maybe_similars.values()
        ),
        "categories_in_main_files": len(openvas_qod_cve.keys()),
        "main_files": openvas_qod_cve_serializable,
        "similars": similars_serializable,
        "maybe_similars": maybe_similars_serializable,
        "NVTS_with_no_CVE": NVTS_with_no_CVE,
    }

    directory_path = os.path.abspath(RESULTS_DIRECTORY_NAME)
    os.makedirs(directory_path, exist_ok=True)
    file_path = os.path.join(directory_path, "info_similarity_NVTS_openvas.json")
    with open(file_path, "w") as json_file:
        json.dump(results, json_file, indent=4)

    return results
