import json
import os
import re
import time
from difflib import SequenceMatcher

from .constants import (PROMPT_OPENVAS_AUTHENTICATED, PROMPT_OPENVAS_EXPLOIT,
                        PROMPT_OPENVAS_NOT_EXPLOIT_NOT_AUTHENTICATED)
from .LLM import LLMHandler
from .utils import find_key_by_value, read_file_with_fallback

# qod values for OpenVAS - https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html#quality-of-detection-concept
QOD_VALUE = {
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

FILE_EXTENSION_OPENVAS = ".nasl"

# these values are arbitrary and can be changed if necessary
SCORE_SIMILAR_FILE = 31
SCORE_MAYBE_SIMILAR_FILE = 16

"""
    This file contains the functions to classify Openvas scripts.
    The classification is done by analyzing the content of the script, extracting metadada using regex and then sending the information to the LLM with the appropriate prompt.
    The classification is done in batches, as there are many files to be classified.
    In particular, Openvas contains almost 100 thousand files, so an initial filtering is done to avoid classifying all files, grouping them in similar categories.
    Below, the functions are described in more detail.
"""

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
def extract_cve_from_openvas(content) -> list:
    cves = CVE_REGEX.findall(content)
    cves_to_list = [cve for match in cves for cve in match if cve]
    return cves_to_list


def is_openvas_file_deprecated(file_content) -> bool:
    match = DEPRECATED_REGEX.search(file_content)
    return bool(match) if match else False


def extract_qod_openvas(content) -> tuple:
    qod_match = QOD_REGEX.search(content)
    if not qod_match:
        return ()

    qod_type = ""
    qod_value = 0

    if qod_match.group("qod_value").isdigit():
        qod_value = int(qod_match.group("qod_value"))
        qod_type = find_key_by_value(QOD_VALUE, qod_value)
        return ()
    else:
        qod_type = qod_match.group("qod_value")
        qod_value = QOD_VALUE[qod_type] if qod_type in QOD_VALUE else None

    if qod_value is None:
        return ()

    return qod_type if qod_type else "", qod_value if qod_value else 0


def extract_oid_openvas(content) -> str:
    match = OID_REGEX.search(content)
    return match.group("oid") if match else ""


def extract_solution_type_openvas(content) -> str:
    solution_type = SOLUTION_TYPE_REGEX.search(content)
    return solution_type.group("value").replace("\n", "") if solution_type else ""


def extract_insight_openvas(content) -> str:
    insight = INSIGHT_REGEX.search(content)
    return insight.group("value").replace("\n", "") if insight else ""


def extract_impact_openvas(content) -> str:
    impact = IMPACT_REGEX.search(content)
    return impact.group("value").replace("\n", "") if impact else ""


def extract_solution_openvas(content) -> str:
    solution = SOLUTION_REGEX.search(content)
    return solution.group("value").replace("\n", "") if solution else ""


def extract_summary_openvas(content) -> str:
    description = SUMMARY_REGEX.search(content)
    return description.group("value").replace("\n", "") if description else ""


def extract_vuldetect_openvas(content) -> str:
    vuldetect = VULDETECT_REGEX.search(content)
    return vuldetect.group("value").replace("\n", "") if vuldetect else ""


def extract_affected_openvas(content) -> str:
    affected = AFFECTED_REGEX.search(content)
    return affected.group("value").replace("\n", "") if affected else ""


def classification_openvas(content, qod_value, qod_type, llm) -> str:
    """
    This function filters the content of the Openvas script and classifies it according to the QOD value and type.
    """
    classification: str = ""

    qod_authenticated_scan = QOD_VALUE[
        "package"
    ]  # QOD_VALUE['registry'] is also a authenticated scan

    if qod_value >= QOD_VALUE["remote_app"] or qod_value == QOD_VALUE["remote_active"]:
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


def analysis_openvas_NVTS(openvas_folder, initial_range, final_range, ip_port) -> tuple:
    """
    How the function works:
        This file handles the classification of Openvas scripts. Useful information is taken from the file metadata to perform the classification, and then sent to the LLM that will perform the task.

        Since there are many files to be classified, the function operates in batches, classifying files in a given range of values.

    Input: Folder with Openvas NVTS and range for classification.

    Output: classified files and information about files without CVE.

    *Classification is not performed on all Openvas files. Check the 'get_list_unique_files' function.
    """

    llm = LLMHandler(ip_port)

    NVTS_with_no_CVE: list = []

    openvas_info: list = []

    openvas_files = get_list_unique_files(openvas_folder)

    for openvas_file in openvas_files[initial_range:final_range]:

        openvas_file = os.path.abspath(openvas_file)

        content = read_file_with_fallback(openvas_file)

        if is_openvas_file_deprecated(content):
            continue

        qod_info = extract_qod_openvas(content)

        if not qod_info:
            continue

        qod_type, qod_value = qod_info

        cves = extract_cve_from_openvas(content)

        if not cves:

            NVTS_with_no_CVE.append(openvas_file)

        oid = extract_oid_openvas(content)

        start_time = time.time()

        classification = classification_openvas(content, qod_value, qod_type, llm)

        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Elapsed time: {elapsed_time:.2f} seconds")

        info = {
            "file": openvas_file,
            "qod": qod_info,
            "cves": cves,
            "oid": oid,
            "classification": classification,
        }

        openvas_info.append(info)

        print(classification)

    return openvas_info, NVTS_with_no_CVE


def similarity_text(a, b):
    return SequenceMatcher(None, a, b).ratio()


def get_file_info(content) -> dict:
    file_affected = extract_affected_openvas(content)
    file_summary = extract_summary_openvas(content)
    file_vuldetect = extract_vuldetect_openvas(content)
    file_solution = extract_solution_openvas(content)
    file_insight = extract_insight_openvas(content)
    file_impact = extract_impact_openvas(content)
    file_vuldetect = extract_vuldetect_openvas(content)
    file_qod_info = extract_qod_openvas(content)

    result = {
        "affected": file_affected,
        "summary": file_summary,
        "vuldetect": file_vuldetect,
        "solution": file_solution,
        "insight": file_insight,
        "impact": file_impact,
        "vuldetect": file_vuldetect,
        "qod": file_qod_info,
    }

    return result


def return_similarity_score(
    new_file_name: str, new_file_info: dict, old_file_name: str, old_file_info: dict
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


def get_list_unique_files(openvas_folder) -> list:

    openvas_checked_files = compare_similarity_openvas(openvas_folder)

    list_unique_files = []
    for value in openvas_checked_files["unique_files"].values():
        list_unique_files += value

    return list_unique_files


def check_active_script(
    qod_value: int, key: str, openvas_qod_cve: dict, openvas_file: str
) -> bool:
    """
    Function to check if a script performs actives checks or not.
    If so, it is important to separate it from the others.
    """

    if qod_value >= QOD_VALUE["remote_app"] or qod_value == QOD_VALUE["remote_active"]:

        # using a new key to separate the active codes
        new_key_active_check = key + " active"

        if new_key_active_check not in openvas_qod_cve:
            openvas_qod_cve[new_key_active_check] = []

        openvas_qod_cve[new_key_active_check].append(openvas_file)

        return True

    return False


def verifies_similarity(
    score: int, key: str, similars: dict, maybe_similars: dict, openvas_file: str
) -> bool:
    """
    This functions verifies if the analyzed file is similar to another file. Based on the score received, it classifies the file as similar or maybe similar to the initial file.
    """

    similar = False

    code_is_similar = score >= SCORE_SIMILAR_FILE
    code_is_maybe_similar = score >= SCORE_MAYBE_SIMILAR_FILE

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


def compare_similarity_openvas(openvas_folder) -> dict[str, dict]:
    """
    How the function works:
        When classifying scripts, since Openvas has almost 100 thousand files, it is important to group similar files to avoid computational costs.

        Grouping is done by deterministically checking file data, such as metadata, script name and QOD. The more common characteristics, the more confidence in the similarity. It is worth noting that not all common characteristics have the same weight, which were determined by script analysis and grouping tests. These values are not absolute and can be changed if necessary.

        Files are classified into 3 groups:

        - Unique = Files with unique characteristics for each set of CVE + QOD

        - Similar = Files that have a high chance of being similar to files marked as unique, sharing several characteristics.

        - Maybe similar = Files that have fewer characteristics in common, but that are probably similar.

        The control for similarity classification can be done by changing the SCORE constants at the beginning of the file, which restrict or facilitate the requirements for grouping.

    Input: Folder with openvas files
    Output: Dictionary with the set of unique, similar, maybe similar and files without CVE.

    * This script also saves the results in a folder 'results' in the file 'info_similarity_NVTS_openvas.json' in the current directory.
    """

    openvas_files = [
        os.path.join(root, file)
        for root, _, files in os.walk(openvas_folder)
        for file in files
        if file.endswith(FILE_EXTENSION_OPENVAS)
    ]

    openvas_qod_cve: dict = {}
    similars: dict = {}
    maybe_similars: dict = {}

    files_skipped: list = []

    NVTS_with_no_CVE = []

    print("Total files ", len(openvas_files))
    for openvas_file in openvas_files:

        new_file_name = os.path.basename(openvas_file)

        content = read_file_with_fallback(openvas_file)

        if is_openvas_file_deprecated(content):
            files_skipped.append(openvas_file)
            continue

        new_file_info = get_file_info(content)

        if not new_file_info["qod"]:
            files_skipped.append(openvas_file)
            continue

        cves: list = extract_cve_from_openvas(content)

        if not (cves):

            NVTS_with_no_CVE.append(openvas_file)

        cves_str: str = ""
        for i in cves:
            cves_str += i + " "

        qod_type, qod_value = new_file_info["qod"]

        # the dict key is the cve checked and the qod
        # with this is possible to separate codes that verifies the same CVE
        key = cves_str + qod_type

        if key not in openvas_qod_cve:
            openvas_qod_cve[key] = []
            openvas_qod_cve[key].append(openvas_file)
            continue

        is_active_code = check_active_script(
            qod_value, key, openvas_qod_cve, openvas_file
        )

        if is_active_code:
            continue

        similar = False

        for old_file in openvas_qod_cve[key]:

            old_file_content = read_file_with_fallback(old_file)

            old_file_info = get_file_info(old_file_content)

            old_file_name = os.path.basename(old_file)

            score = return_similarity_score(
                new_file_name, new_file_info, old_file_name, old_file_info
            )

            similar = verifies_similarity(
                score, key, similars, maybe_similars, openvas_file
            )

            if similar == True:
                break

        if similar is False:
            openvas_qod_cve[key].append(openvas_file)

    results: dict = {
        "number_skipped_files": len(files_skipped),
        "number_unique_files": sum(len(value) for value in openvas_qod_cve.values()),
        "number_similar_files": sum(len(value) for value in similars.values()),
        "number_maybe_similar_files": sum(
            len(value) for value in maybe_similars.values()
        ),
        "categories_in_unique_files": len(openvas_qod_cve.keys()),
        "unique_files": openvas_qod_cve,
        "similars": similars,
        "maybe_similars": maybe_similars,
        "NVTS_with_no_CVE": NVTS_with_no_CVE,
    }

    directory_path = os.path.abspath("results")
    os.makedirs(directory_path, exist_ok=True)
    file_path = os.path.join(directory_path, "info_similarity_NVTS_openvas.json")
    with open(file_path, "w") as json_file:
        json.dump(results, json_file, indent=4)

    return results
