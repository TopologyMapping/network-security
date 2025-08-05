"""
This module provides functionality for classifying Nmap scripts.

The classification process involves:
1. Analyzing the content of each script and extracting metadata using regular expressions.
2. Sending the extracted information to a language model (LLM) with a specific prompt for classification.
3. Organizing the scripts into appropriate categories based on the LLM's responses.

The classification is performed in batches to efficiently handle large numbers of files.
"""

import dataclasses
import os
import re
import time

from dataclasses_json import dataclass_json

from .constants import (PROMPT_NMAP, PROMPT_NMAP_ATTACK, PROMPT_NMAP_BRUTE_DOS,
                        PROMPT_NMAP_DISCOVERY)
from .llm import LLMHandler
from .utils import ScriptClassificationResult, read_file_with_fallback

FILE_EXTENSION_NMAP = ".nse"

BRUTE_FORCE_CATEGORY = "brute"
DOS_CATEGORY = "dos"
DISCOVERY_CATEGORY = "discovery"
SAFE_CATEGORY = "safe"
INTRUSIVE_CATEGORIES : set = {"exploit", "malware", "vuln"}
EXPLOIT_CATEGORY = "exploit"
MALWARE_CATEGORY = "malware"
VULN_CATEGORY = "vuln"

NMAP_CVE_REGEX = re.compile(r"IDS\s*=\s*\{.*CVE\s*=\s*'(?P<cve>[^']+)'.*\}")
NMAP_CATEGORIES_REGEX = re.compile(r"categories\s*=\s*\{(?P<categories>[^\}]+)\}")


# class to organize information about the Nmap script
@dataclass_json
@dataclasses.dataclass
class NmapScriptInfo:
    file: str
    classification: str
    id: str  # the Nmap id is the file name
    cves: list
    categories: list[str]


# REGEX FUNCTIONS TO EXTRACT INFO
def extract_cve_nmap(content) -> list:
    cves = [match.group("cve") for match in NMAP_CVE_REGEX.finditer(content)]
    return cves if cves else []


def extract_categories_nmap(content) -> list[str]:
    match = NMAP_CATEGORIES_REGEX.search(content)
    if match:
        categories = match.group("categories")
        words = [word.strip('"') for word in categories.split(",")]
        return words
    return []


def classification_nmap(
    all_script_categories: list[str], content: str, llm: LLMHandler
) -> str:
    """
    This function filters the content of the Nmap script and classifies it according to the categorie collected.

    Using some information form the script (categories), is possible to deterministcally classify the script, reducing the amount of work for the LLM.
    """

    classification: str = ""

    if BRUTE_FORCE_CATEGORY in all_script_categories:
        classification = llm.classification_text_generation(
            content, PROMPT_NMAP_BRUTE_DOS
        )

        category_and_subcategory_privileged_exploit = """ 

        How the script works?
        Category: {Simulated Attack}
        Subcategory: {Unauthorized Login}

        """

        classification += category_and_subcategory_privileged_exploit

    elif DOS_CATEGORY in all_script_categories:
        classification = llm.classification_text_generation(
            content, PROMPT_NMAP_BRUTE_DOS
        )

        category_and_subcategory_dos = """ 

        How the script works?
        Category: {Simulated Attack}
        Subcategory: {Denial of Service (DoS)}

        """

        classification += category_and_subcategory_dos

    elif (
        DISCOVERY_CATEGORY in all_script_categories
        and SAFE_CATEGORY in all_script_categories
    ):
        # 'safe' included because there is 'intrusive' codes that receives 'discovery' categorie, even when performs attacks
        classification = llm.classification_text_generation(
            content, PROMPT_NMAP_DISCOVERY
        )

        category_and_subcategory_discovery_safe = """ 

        How the script works?
        Category: {Basic Active Requests}
        Subcategory: {Discovery}

        """

        classification += category_and_subcategory_discovery_safe

    elif INTRUSIVE_CATEGORIES.intersection(all_script_categories) and SAFE_CATEGORY not in all_script_categories:

        classification = llm.classification_text_generation(content, PROMPT_NMAP_ATTACK)

    else:
        classification = llm.classification_text_generation(content, PROMPT_NMAP)

    return classification


def analysis_nmap_scripts(
    nmap_folder: str, initial_range: int, final_range: int, ip_port: str
) -> ScriptClassificationResult:
    """
    How the function works:
        This file handles the classification of Nmap scripts. Useful information is taken from the file metadata to perform the classification, and then sent to the LLM that will perform the task.

        Since there are many files to be classified, the function operates in batches, classifying files in a given range of values.

    Input: Folder with Nmap scripts and range for classification.

    Output: classified files and information about files without CVE.
    """

    llm = LLMHandler(ip_port)

    scripts_with_no_CVE: list[str] = []

    nmap_info: list[NmapScriptInfo] = []

    nmap_files = [
        os.path.join(root, file)
        for root, _, files in os.walk(nmap_folder)
        for file in files
        if file.endswith(FILE_EXTENSION_NMAP)
    ]

    # sorting files by name to ensure the order of classification
    nmap_files = sorted(nmap_files, key=lambda file: os.path.basename(file))

    for nmap_file in nmap_files[initial_range:final_range]:

        content = read_file_with_fallback(nmap_file)

        cves = extract_cve_nmap(content)

        if not cves:

            scripts_with_no_CVE.append(nmap_file)

        categories : list[str] = extract_categories_nmap(content)

        file_name : str = os.path.basename(nmap_file)

        start_time = time.time()

        classification : str = classification_nmap(categories, content, llm)

        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Elapsed time: {elapsed_time:.2f} seconds")

        info = NmapScriptInfo(
            file=nmap_file,
            cves=cves,
            name=file_name,
            categories=categories,
            classification=classification,
        ).to_dict()

        nmap_info.append(info)

    return ScriptClassificationResult(
        scripts_with_cves=nmap_info, scripts_without_cves=scripts_with_no_CVE
    )
