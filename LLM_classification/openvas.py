import re
from utils import (
    read_file_with_fallback,
    find_key_by_value,
    classification_text_generation,
)
import os
import time
import json
from difflib import SequenceMatcher
from constants import (
    QOD_VALUE,
    PROMPT_OPENVAS_EXPLOIT,
    PROMPT_OPENVAS_AUTHENTICATED,
    PROMPT_OPENVAS_NOT_EXPLOIT_NOT_AUTHENTICATED,
    FILE_EXTENSION_OPENVAS,
)

SCORE_SIMILAR_FILE = 31
SCORE_MAYBE_SIMILAR_FILE = 16


def extract_cve_from_openvas(content):
    """ "
    TODO: Double check this regex
    """

    cve_regex = re.compile(r'script_cve_id\("([^"]+)"(?:,\s*"([^"]+)")*\);')
    cves = cve_regex.findall(content)
    cves_to_list = [cve for match in cves for cve in match if cve]

    return cves_to_list


def is_openvas_file_deprecated(file_content):
    deprecated_regex = re.compile(r'script_tag\(name:"deprecated",\s*value:TRUE\);')
    return deprecated_regex.search(file_content) is not None


def extract_qod_openvas(content):

    qod_regex = re.compile(r'script_tag\(name:"(qod|qod_type)",\s*value:"([^"]+)"\);')

    qod_match = qod_regex.search(content)

    if not qod_match:
        return ""

    qod_type = ""
    qod_value = 0

    # skipping this case because if only the number, its not possible to know the qod_type
    if qod_match.group(
        2
    ).isdigit():  # return the value in regex. Could be qod_type or string
        qod_value = int(qod_match.group(2))
        qod_type = find_key_by_value(QOD_VALUE, qod_value)

        return ""
    else:
        qod_type = qod_match.group(2)
        qod_value = QOD_VALUE[qod_type] if qod_type in QOD_VALUE else None

    if qod_value is None:
        return ""

    return qod_type if qod_type else "", qod_value if qod_value else 0


def extract_oid_openvas(content):
    oid_regex = re.compile(r'script_oid\("([\d.]+)"\)')
    match = oid_regex.search(content)
    return match.group(1) if match else ""


def extract_solution_type_openvas(content):

    solution_type_regex = re.compile(
        r'script_tag\(name:"solution_type",\s*value:"([^"]+)"\);'
    )

    solution_type = solution_type_regex.search(content)

    if not solution_type:
        return ""

    return solution_type.group(1).replace("\n", "")


def extract_insight_openvas(content):

    insight_regex = re.compile(r'script_tag\(name:"insight",\s*value:"([^"]+)"\);')

    insight = insight_regex.search(content)

    if not insight:
        return ""

    return insight.group(1).replace("\n", "")


def extract_impact_openvas(content):

    impact_regex = re.compile(r'script_tag\(name:"impact",\s*value:"([^"]+)"\);')

    impact = impact_regex.search(content)

    if not impact:
        return ""

    return impact.group(1).replace("\n", "")


def extract_solution_openvas(content):

    solution_regex = re.compile(r'script_tag\(name:"solution",\s*value:"([^"]+)"\);')

    solution = solution_regex.search(content)

    if not solution:
        return ""

    return solution.group(1).replace("\n", "")


def extract_summary_openvas(content):

    summary_regex = re.compile(r'script_tag\(name:"summary",\s*value:"([^"]+)"\);')

    description = summary_regex.search(content)

    if not description:
        return ""

    return description.group(1).replace("\n", "")


def extract_vuldetect_openvas(content):

    vuldetect_regex = re.compile(r'script_tag\(name:"vuldetect",\s*value:"([^"]+)"\);')

    vuldetect = vuldetect_regex.search(content)

    if not vuldetect:
        return ""

    return vuldetect.group(1).replace("\n", "")


def extract_affected_openvas(content):

    affected_regex = re.compile(r'script_tag\(name:"affected",\s*value:"([^"]+)"\);')

    affected = affected_regex.search(content)

    if not affected:
        return ""

    return affected.group(1).replace("\n", "")


def classification_openvas(content, qod_value, qod_type):
    """
    This function filters the content of the Openvas script and classifies it according to the QOD value and type.
    """

    qod_authenticated_scan = QOD_VALUE[
        "package"
    ]  # QOD_VALUE['registry'] is also a authenticated scan

    if qod_value >= QOD_VALUE["remote_app"] or qod_value == QOD_VALUE["remote_active"]:
        classification = classification_text_generation(content, PROMPT_OPENVAS_EXPLOIT)
    elif qod_value == qod_authenticated_scan or qod_type == "executable_version":
        classification = classification_text_generation(
            content, PROMPT_OPENVAS_AUTHENTICATED
        )
    else:
        classification = classification_text_generation(
            content, PROMPT_OPENVAS_NOT_EXPLOIT_NOT_AUTHENTICATED
        )

    return classification


def analysis_openvas_NVTS(openvas_folder, initial_range, final_range):
    """
    How the function works:
        This file handles the classification of Openvas scripts. Useful information is taken from the file metadata to perform the classification, and then sent to the LLM that will perform the task.

        Since there are many files to be classified, the function operates in batches, classifying files in a given range of values.

    Input: Folder with Openvas NVTS and range for classification.

    Output: classified files and information about files without CVE.

    *Classification is not performed on all Openvas files. Check the 'get_list_unique_files' function.
    """

    NVTS_with_no_CVE = []

    openvas_info = []

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

        classification = classification_openvas(content, qod_value, qod_type)

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


def get_file_info(content):
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


def return_similarity_score(new_file_name, new_file_info, old_file_name, old_file_info):
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


def get_list_unique_files(openvas_folder):

    openvas_checked_files = compare_similarity_openvas(openvas_folder)

    list_unique_files = []
    for value in openvas_checked_files['unique_files'].values():
        list_unique_files += value

    return list_unique_files


def check_active_script(qod_value, key, openvas_qod_cve, openvas_file):
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

        return True, openvas_qod_cve

    return False, openvas_qod_cve


def verifies_similarity(score, key, similars, maybe_similars, openvas_file):

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

        new_file_name = openvas_file.split("/")[-1]

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

        is_active_code, openvas_qod_cve = check_active_script(
            qod_value, key, openvas_qod_cve, openvas_file
        )

        if is_active_code:
            continue

        similar = False

        for old_file in openvas_qod_cve[key]:

            old_file_content = read_file_with_fallback(old_file)

            old_file_info = get_file_info(old_file_content)

            old_file_name = old_file.split("/")[-1]

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
