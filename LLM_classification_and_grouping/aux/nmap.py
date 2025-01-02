import dataclasses
import os
import re
import time

from dataclasses_json import dataclass_json

from .constants import (PROMPT_NMAP, PROMPT_NMAP_ATTACK, PROMPT_NMAP_BRUTE_DOS,
                        PROMPT_NMAP_DISCOVERY)
from .llm import LLMHandler
from .utils import ScriptClassificationResult, read_file_with_fallback

"""
    This file contains the functions to classify Nmap scripts.
    The classification is done by analyzing the content of the script, extracting metadada using regex and then sending the information to the LLM with the appropriate prompt.
    The classification is done in batches, as there are many files to be classified.
    Below, the functions are described in more detail.
"""
FILE_EXTENSION_NMAP = ".nse"

BRUTE_FORCE_CATEGORY = "brute"
DOS_CATEGORY = "dos"
DISCOVERY_CATEGORY = "discovery"
SAFE_CATEGORY = "safe"
INTRUSIVE_CATEGORIES = ["exploit", "malware", "vuln"]

NMAP_CVE_REGEX = re.compile(r"IDS\s*=\s*\{.*CVE\s*=\s*'(?P<cve>[^']+)'.*\}")
NMAP_CATEGORIES_REGEX = re.compile(r"categories\s*=\s*\{(?P<categories>[^\}]+)\}")


# class to organize information about the Nmap script
@dataclass_json
@dataclasses.dataclass
class NmapScriptInfo:
    file: str
    classification: str
    id: str # the Nmap id is the file name
    cves: list
    categories: str


# REGEX FUNCTIONS TO EXTRACT INFO
def extract_cve_nmap(content) -> list:
    cves = [match.group("cve") for match in NMAP_CVE_REGEX.finditer(content)]
    return cves if cves else []


def extract_categorie_nmap(content) -> str:
    match = NMAP_CATEGORIES_REGEX.search(content)
    if match:
        categories = match.group("categories")
        words = [word.strip('"') for word in categories.split(",")]
        return " ".join(words)
    return ""


def classification_nmap(categorie: str, content, llm) -> str:
    """
    This function filters the content of the Nmap script and classifies it according to the categorie collected.
    """

    classification: str = ""

    if BRUTE_FORCE_CATEGORY in categorie:
        classification = llm.classification_text_generation(
            content, PROMPT_NMAP_BRUTE_DOS
        )

        category_privileged_exploit = """ 

        How the script works?
        Category: {Simulated Attack}
        Subcategory: {Unauthorized Login}

        """

        classification += category_privileged_exploit

    elif DOS_CATEGORY in categorie:
        classification = llm.classification_text_generation(
            content, PROMPT_NMAP_BRUTE_DOS
        )

        category_privileged_exploit = """ 

        How the script works?
        Category: {Simulated Attack}
        Subcategory: {Denial of Service (DoS)}

        """

        classification += category_privileged_exploit

    elif DISCOVERY_CATEGORY in categorie and SAFE_CATEGORY in categorie:
        # 'safe' included because there is 'intrusive' codes that receives 'discovery' categorie, even when performs attacks
        classification = llm.classification_text_generation(
            content, PROMPT_NMAP_DISCOVERY
        )

        category_privileged_exploit = """ 

        How the script works?
        Category: {Basic Active Requests}
        Subcategory: {Discovery}

        """

        classification += category_privileged_exploit

    elif (
        any(intrusive in categorie for intrusive in INTRUSIVE_CATEGORIES)
    ) and SAFE_CATEGORY not in categorie:

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

    scripts_with_no_CVE: list = []

    nmap_info: list = []

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

        categories = extract_categorie_nmap(content)

        file_name = os.path.basename(nmap_file)

        start_time = time.time()

        classification = classification_nmap(categories, content, llm)

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
