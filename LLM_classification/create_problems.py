"""
This script is responsible for processing the classification answers from the LLM model.
It is important to run the 'distributed_classification.py' script before running this script, because it generates the classification answers that are used here. Also, its important to have multiples classification answers to have a good grouping of the scripts.
The results of this script are stored in a JSON file, containing the 'problems' (categories) to group the scripts and the 'errors' (scripts that could not be grouped).
"""

import argparse
import os
import json
import re
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from collections import defaultdict

from openvas import extract_oid_openvas
from nuclei import extract_nuclei_id
from utils import read_file_with_fallback

nltk.download("punkt_tab")
nltk.download("stopwords")
STOP_WORDS = set(stopwords.words("english"))

VALUES_WHAT_IS_DETECTED = [
    "Vulnerability",
    "Old Software",
    "Properties of a System",
    "Unmaintained Software",  # these values are not the correct categories, but they are present on the results 
    "Property of a System",
]

VALUES_CATEGORY = ["SimulatedAttack", "PrivilegedScan", "BasicActiveRequests"]

VALUES_SUBCATEGORY = [
    "ExternalCodeExecution",
    "UnauthorizedLogin",
    "ProtectedInformation",
    "DenialofServiceDoS", 
    "PrivilegedAttack",
    "PackageList",
    "Serviceinformation",
    "LogFileAnalysis",
    "BannerCheck",
    "URLPresenceCheck",
    "Discovery",
]

LLM_ERROR = "Error in LLM answer"
REGEX_ERROR = "Error in regex match"

TASK1_PATTERN = (
    r"What is detected:\s*\n*\{?(.*?)\}?\s*\n*A:\s*(.*?)\s*\n*B:\s*\{?(.*?)\}?"
)
TASK2_PATTERN = r"Category:\s*\{?(.*?)\}?\s*Subcategory:\s*\{?(.*?)\}?\s*(?:\n|$)"
NON_ALPHANUMERIC_REGEX = r"[^\w\s]"
NUMERIC_REGEX = r"\d+"
CATEGORY_SUBCATEGORY_CLEANUP_REGEX = r"[ .\n]"


def extract_task_information(classification_text) -> dict:
    """
    Extracts Task 1 and Task 2 information from the classification text.
    Task 1 refers to the 'what is detected', 'application' and 'version' fields.
    Task 2 refers to the 'category' and 'subcategory' fields.

    The 'version' could be used to improve the grouping, but it is not used in this implementation, because the values are too variables, so its hard to match the scripts based on this field. But in the future it can be improved.

    Input: the LLM classification answer.
    Output: a dictionary with the extracted information.
    """

    # Search for Task 1 and Task 2 using regex patterns
    task1_match = re.search(TASK1_PATTERN, classification_text, re.DOTALL)
    task2_match = re.search(TASK2_PATTERN, classification_text, re.DOTALL)

    # Process Task 1 fields
    task1_what_is_detected = (
        re.sub(NON_ALPHANUMERIC_REGEX, "", task1_match.group(1).strip())
        if task1_match
        else " "
    )
    task1_application = (
        re.sub(NON_ALPHANUMERIC_REGEX, "", task1_match.group(2).strip())
        if task1_match
        else " "
    )

    # Process Task 2 fields
    task2_category = (
        re.sub(NON_ALPHANUMERIC_REGEX, "", task2_match.group(1).strip())
        if task2_match
        else " "
    )
    task2_subcategory = (
        re.sub(NON_ALPHANUMERIC_REGEX, "", task2_match.group(2).strip())
        if task2_match
        else " "
    )

    # Clean up values
    task2_category = task2_category.replace("Category", "")
    task2_subcategory = task2_subcategory.replace("Subcategory", "")

    task1_what_is_detected = re.sub(NUMERIC_REGEX, "", task1_what_is_detected).replace(
        "\n", ""
    )
    task1_application = re.sub(NUMERIC_REGEX, "", task1_application).replace("\n", "")

    if task1_what_is_detected == "Property of a System":
        task1_what_is_detected = "Properties of a System"

    task2_category = (
        re.sub(NUMERIC_REGEX, "", task2_category)
        .replace(".", "")
        .replace(" ", "")
        .replace("\n", "")
    )
    task2_subcategory = (
        re.sub(NUMERIC_REGEX, "", task2_subcategory)
        .replace(".", "")
        .replace(" ", "")
        .replace("\n", "")
    )

    # Validation checks
    if task2_subcategory == "" or task2_category == "" or task1_what_is_detected == "":
        raise Exception(REGEX_ERROR)

    if (
        task2_subcategory not in VALUES_SUBCATEGORY
        or task2_category not in VALUES_CATEGORY
        or task1_what_is_detected not in VALUES_WHAT_IS_DETECTED
    ):
        raise Exception(LLM_ERROR)

    # Return extracted information
    information = {
        "what_is_detected": task1_what_is_detected,
        "application": task1_application,
        "category": task2_category,
        "subcategory": task2_subcategory,
    }

    return information


def check_if_scripts_application_contains_similar_tokens(
    applications, filtered_tokens
) -> str:
    for key in applications:

        tokens_key = key.split("_")

        for i in tokens_key:
            for j in filtered_tokens:
                if i in j or j in i:
                    return key
    return ""


def sort_problems(problems):
    """
    This function sorts the problems dictionary by the length of the innermost list. There is no need to do this, but it is useful to see the results of the grouping.
    """
    sorted_problems = {}
    for cve, cve_dicts in problems.items():
        sorted_problems[cve] = {}
        for task2, task2_dict in cve_dicts.items():
            sorted_problems[cve][task2] = {}
            for (
                task1_what_is_detected,
                task1_what_is_detected_dict,
            ) in task2_dict.items():
                # Sort by the length of the innermost list
                sorted_problems[cve][task2][task1_what_is_detected] = dict(
                    sorted(task1_what_is_detected_dict.items(), key=lambda x: len(x[1]))
                )
    return sorted_problems


def filter_classification_text(
    classification_text, errors_LLM, errors_regex, info_to_store
) -> dict:
    info = {}
    try:
        info = extract_task_information(classification_text)
    except Exception as e:
        if REGEX_ERROR in str(e):
            errors_regex.append(info_to_store)
        elif LLM_ERROR in str(e):
            errors_LLM.append(info_to_store)

    return info


def grouping_info(
    problems: dict,
    cves: list,
    category_subcategory: str,
    what_is_detected: str,
    application: str,
    info_to_store: str,
    errors_LLM: list,
):
    """
    This function groups the information extracted from the classification text.
    The ideia is to group the classified scripts by):
        - CVE (deterministic information, the most constant)
        - Task2 (category and subcategory) -> not so constant, but the LLM is restricted to a few options
        - Task1 (what is detected) -> the same case as before
        - Task1 (application name) -> the most variable information. Could be any string

    To handle the variability of the application name, the value is tokenized and then is compared the similarity between the tokens of the application name and the tokens of the already classified scripts. If the current script contains similar tokens, then they are grouped together. Otherwise, a new group is created.

    This functions performs changes in the 'problems' dictionary and in the 'errors_LLM' list. So nothing is returned.

    """
    # starting grouping by CVE -> most constant info
    for cves_key in cves:

        if cves_key not in problems:
            problems[cves_key] = {}

        # grouping by constant info again (task2 refers to the category and subcategory)
        if category_subcategory not in problems[cves_key]:
            problems[cves_key][category_subcategory] = {}

        if what_is_detected not in problems[cves_key][category_subcategory]:
            problems[cves_key][category_subcategory][what_is_detected] = {}

        tokens_application = word_tokenize(application.lower())

        filtered_tokens_application = [
            word for word in tokens_application if word.lower() not in STOP_WORDS
        ]

        # if the application name contains too much tokens, it is not useful for grouping (could be a LLM error). The value 6 is arbitrary
        CHECK_IF_APPLICATION_NAME_IS_TOO_LONG = len(filtered_tokens_application)
        if CHECK_IF_APPLICATION_NAME_IS_TOO_LONG > 6:
            errors_LLM.append(info_to_store)
            return

        # starting grouping by the classified application name. Too variable info, so it is the last to be grouped

        # storing the tokens in a string to be used as a key
        key_tokens_taks1_application = "_".join(filtered_tokens_application) + "_"

        application_tokens_list = problems[cves_key][category_subcategory][
            what_is_detected
        ].keys()

        match_application_tokens = check_if_scripts_application_contains_similar_tokens(
            application_tokens_list, filtered_tokens_application
        )

        if match_application_tokens:
            problems[cves_key][category_subcategory][what_is_detected][
                match_application_tokens
            ].append(info_to_store)
            return

        problems[cves_key][category_subcategory][what_is_detected][
            key_tokens_taks1_application
        ] = []
        problems[cves_key][category_subcategory][what_is_detected][
            key_tokens_taks1_application
        ].append(info_to_store)

    return


def organizing_grouping_structure(result: dict):
    """
    This function is responsible for organizing the grouping structure of the scripts. The structure presented before as CVES -> Task2 -> Task1 -> Application on the function 'process_json_files' is good to improve the understanding of the grouping. But to store the information to be used in Defect Dojo application, it is better to store the information as a list of scripts grouped together.

    The scripts names are changed to the respective ID, so the information could be used in the Defect Dojo application.

    The 'metasploit' files are ignored because they are not used in the Defect Dojo application. But if this could be possible in the future, the 'metasploit' files could be included in the grouping structure.

    The output is stored in ./results/problems.json
    """
    organized_grouping = defaultdict(list)

    # Traverse the nested dictionary structure
    for cve, attacks in result["problems"].items():
        for attack, attack_details in attacks.items():
            for vuln_type, vuln_paths in attack_details.items():
                for vuln_name, files in vuln_paths.items():
                    for file_path in files:

                        # the 'grouping' value is the information in common between the scripts, separated by '@'
                        value = cve + "@" + attack + "@" + vuln_type + "@" + vuln_name

                        # the values were stored as 'file_with_classification' - 'script_name'
                        script_name = file_path.split(" - ")[1]

                        if "metasploit" in script_name:
                            continue

                        try:
                            file_content = read_file_with_fallback(script_name)
                        except:
                            print("File not found: ", script_name)
                            continue

                        if "openvas" in script_name:
                            id = extract_oid_openvas(file_content)
                        elif "nuclei" in script_name:
                            id = extract_nuclei_id(file_content)
                        elif "nmap" in script_name:
                            id = os.path.basename(script_name).split(".")[
                                0
                            ]  # removing file extension
                        else:
                            id = script_name

                        organized_grouping[value].append(id)

    # Convert defaultdict to a regular dict
    inverted_dict = dict(organized_grouping)

    # removing the keys that have only one value, because they are not grouped
    keys_to_delete = [
        key
        for key, value in inverted_dict.items()
        if isinstance(value, (list, set)) and len(value) == 1
    ]
    for key in keys_to_delete:
        del inverted_dict[key]

    with open("./results/problems.json", "w") as f:
        json.dump(inverted_dict, f, indent=4)


def process_json_files(folder_path):
    """
    Processes JSON files in the folder and extracts required information.
    :param folder_path: Path to the folder containing JSON files.
    :param output_folder: Path to the folder to save the processed files.

    Important: The input file must be a JSON file containing the classification information of the scripts, performed by the code in the 'distributed_classification.py' script. The input file also needs to end with the string '_classification.json'.

    The output is stored in a JSON file called 'grouped_scripts.json'.
    """

    problems: dict = {}
    errors_LLM: list = []
    errors_regex: list = []

    for file_name in os.listdir(folder_path):
        if file_name.endswith("_classification.json"):
            file_path = os.path.join(folder_path, file_name)

            with open(file_path, "r") as file:
                data = json.load(file)

            for scan_app in data.keys():

                if scan_app == "tests_with_no_CVE":
                    continue

                for entry in data[scan_app]:

                    cves = entry["cves"]

                    # if there is no CVE, it is stored as an empty string
                    if cves == []:
                        cves = [""]

                    # storing results of grouping as the classificaiton file where the script was classified together with the script name
                    info_to_store = file_name + " - " + entry["file"]

                    classification_info_extracted = filter_classification_text(
                        entry["classification"], errors_LLM, errors_regex, info_to_store
                    )

                    if not classification_info_extracted:
                        continue

                    info = classification_info_extracted

                    what_is_detected = info["what_is_detected"]
                    application = info["application"]
                    category = info["category"]
                    subcategory = info["subcategory"]

                    category_subcategory = category + "_" + subcategory

                    grouping_info(
                        problems,
                        cves,
                        category_subcategory,
                        what_is_detected,
                        application,
                        info_to_store,
                        errors_LLM,
                    )

    sorted_problems = sort_problems(problems)

    result = {
        "len_problems": len(sorted_problems),
        "len_errors_LLM": len(errors_LLM),
        "len_errors_regex": len(errors_regex),
        "problems": sorted_problems,
        "errors_LLM": errors_LLM,
        "errors_regex": errors_regex,
    }

    # Save processed data
    with open("./results/grouped_scripts.json", "w") as f:
        json.dump(result, f, indent=4)

    organizing_grouping_structure(result)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Match classification between Nmap, OpenVAS, and Nuclei"
    )
    parser.add_argument("--input", required=False, help="input folder")

    args = parser.parse_args()

    # Process JSON files
    process_json_files(args.input)
