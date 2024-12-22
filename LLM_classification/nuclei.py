import re
import time
import os
from utils import read_file_with_fallback
from constants import (
    PROMPT_NUCLEI,
    PROMPT_NUCLEI_REMOTE_CODE_EXECUTION,
    PROMPT_NUCLEI_AUTH_BYPASS,
)
from LLM import LLMHandler


"""
    This file contains the functions to classify Nuclei scripts.
    The classification is done by analyzing the content of the script, extracting metadada using regex and then sending the information to the LLM with the appropriate prompt.
    The classification is done in batches, as there are many files to be classified.
    Below, the functions are described in more detail.
"""

CVE_NUCLEI_REGEX = re.compile(r"cve-id:\s*(?P<cve>CVE-[\d-]+)")
NUCLEI_ID_REGEX = re.compile(r"id:\s*(?P<id>[\w\-]+)")
NUCLEI_TAGS_REGEX = re.compile(r"tags:\s*(?P<tags>[\w,\-]+)")

# REGEX FUNCTIONS TO EXTRACT INFO
def extract_cve_nuclei(content) -> list:
    cves = [match.group("cve") for match in CVE_NUCLEI_REGEX.finditer(content)]
    return cves if cves else []

def extract_nuclei_id(content) -> str:
    match = NUCLEI_ID_REGEX.search(content)
    return match.group("id") if match else ""

def extract_nuclei_tags(content) -> list:
    match = NUCLEI_TAGS_REGEX.search(content)
    return match.group("tags").split(",") if match else []


def classification_nuclei(tags, content, llm) -> str:
    """
    This function filters the content of the Nuclei script and classifies it according to the tags collected.
    """
    classification : str = ""

    if "rce" in tags or "sqli" in tags or "xss" in tags or "injection" in tags:

        classification = llm.classification_text_generation(
            content, PROMPT_NUCLEI_REMOTE_CODE_EXECUTION
        )

        category_remote_code_exec = """ 

        How the script works?
        Category: {Simulated Attack}
        Subcategory: {External Code Execution}

        """

        classification += category_remote_code_exec

    elif "auth-bypass" in tags or "unauth" in tags or "default-login" in tags:

        classification = llm.classification_text_generation(
            content, PROMPT_NUCLEI_AUTH_BYPASS
        )

        category_auth_bypass = """ 

        How the script works?
        Category: {Simulated Attack}
        Subcategory: {Unauthorized Login}

        """

        classification += category_auth_bypass
    else:
        classification = llm.classification_text_generation(content, PROMPT_NUCLEI)

    return classification


def analysis_nuclei_templates(nuclei_folder, initial_range, final_range, ip_port) -> tuple:
    """
    How the function works:
        This file handles the classification of Nuclei scripts. Useful information is taken from the file metadata to perform the classification, and then sent to the LLM that will perform the task.

        Since there are many files to be classified, the function operates in batches, classifying files in a given range of values.

    Input: Folder with Nuclei templates and range for classification.

    Output: classified files and information about files without CVE.
    """

    llm = LLMHandler(ip_port)

    templates_with_no_CVE : list = []

    nuclei_info : list = []

    nuclei_files = [
        os.path.join(root, file)
        for root, _, files in os.walk(nuclei_folder)
        for file in files
        if file.endswith(".yaml")
    ]

    # sorting files by name to ensure the order of classification
    nuclei_files = sorted(
        nuclei_files,
        key=lambda file: os.path.basename(file)
    )

    print("Len nuclei files ", len(nuclei_files))

    for nuclei_file in nuclei_files[initial_range:final_range]:

        content = read_file_with_fallback(nuclei_file)

        cves = extract_cve_nuclei(content)

        if not (cves):

            templates_with_no_CVE.append(nuclei_file)

        id = extract_nuclei_id(content)

        tags = extract_nuclei_tags(content)

        start_time = time.time()

        classification = classification_nuclei(tags, content, llm)

        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Elapsed time: {elapsed_time:.2f} seconds")

        info = {
            "file": nuclei_file,
            "cves": cves,
            "id": id,
            "classification": classification,
        }

        nuclei_info.append(info)

    return nuclei_info, templates_with_no_CVE
