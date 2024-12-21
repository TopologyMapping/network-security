import re
from utils import read_file_with_fallback, classification_text_generation
from constants import (
    PROMPT_NMAP,
    PROMPT_NMAP_BRUTE_DOS,
    PROMPT_NMAP_DISCOVERY,
    PROMPT_NMAP_ATTACK,
)
import time
import os

"""
    This file contains the functions to classify Nmap scripts.
    The classification is done by analyzing the content of the script, extracting metadada using regex and then sending the information to the LLM with the appropriate prompt.
    The classification is done in batches, as there are many files to be classified.
    Below, the functions are described in more detail.
"""

# REGEX FUNCTIONS TO EXTRACT INFO
def extract_cve_from_nmap(nmap_file):
    cve_regex = re.compile(r"IDS\s*=\s*\{.*CVE\s*=\s*'([^']+)'.*\}")
    content = read_file_with_fallback(nmap_file)
    cves = cve_regex.findall(content)
    return cves


def extract_cve_nmap(content):

    cve_regex = re.compile(r"IDS\s*=\s*\{.*CVE\s*=\s*'([^']+)'.*\}")
    cves = cve_regex.findall(content)
    return cves if cves else ""


def extract_categorie_nmap(content):

    categorie_regex = re.compile(r"categories\s*=\s*\{([^\}]+)\}")
    categories = categorie_regex.findall(content)

    result = ""
    if categories:
        words = [word.strip('"') for word in categories[0].split(",")]
        result = " ".join(words)

    return result


def classification_nmap(categorie, content):
    """
    This function filters the content of the Nmap script and classifies it according to the categorie collected.
    """

    if "brute" in categorie:
        classification = classification_text_generation(content, PROMPT_NMAP_BRUTE_DOS)

        category_privileged_exploit = """ 

        How the script works?
        Category: {Simulated Attack}
        Subcategory: {Unauthorized Login}

        """

        classification += category_privileged_exploit

    elif "dos" in categorie:
        classification = classification_text_generation(content, PROMPT_NMAP_BRUTE_DOS)

        category_privileged_exploit = """ 

        How the script works?
        Category: {Simulated Attack}
        Subcategory: {Denial of Service (DoS)}

        """

        classification += category_privileged_exploit

    elif (
        "discovery" in categorie and "safe" in categorie
    ):  # 'safe' included because there is 'intrusive' codes that receives 'discovery' categorie, even when performs attacks
        classification = classification_text_generation(content, PROMPT_NMAP_DISCOVERY)

        category_privileged_exploit = """ 

        How the script works?
        Category: {Basic Active Requests}
        Subcategory: {Discovery}

        """

        classification += category_privileged_exploit

    elif (
        "exploit" in categorie or "malware" in categorie or "vuln" in categorie
    ) and "safe" not in categorie:

        classification = classification_text_generation(content, PROMPT_NMAP_ATTACK)

    else:
        classification = classification_text_generation(content, PROMPT_NMAP)

    return classification


def analysis_nmap_scripts(nuclei_folder, initial_range, final_range):
    """
    How the function works:
        This file handles the classification of Nmap scripts. Useful information is taken from the file metadata to perform the classification, and then sent to the LLM that will perform the task.

        Since there are many files to be classified, the function operates in batches, classifying files in a given range of values.

    Input: Folder with Nmap scripts and range for classification.

    Output: classified files and information about files without CVE.
    """

    scripts_with_no_CVE = []

    nmap_info = []

    nmap_files = [
        os.path.join(root, file)
        for root, _, files in os.walk(nuclei_folder)
        for file in files
        if file.endswith(".nse")
    ]

    for nmap_file in nmap_files[initial_range:final_range]:

        content = read_file_with_fallback(nmap_file)

        cves = extract_cve_nmap(content)

        if not (cves):

            scripts_with_no_CVE.append(nmap_file)

        categorie = extract_categorie_nmap(content)

        file_name = nmap_file.split("/")[-1]

        start_time = time.time()

        classification = classification_nmap(categorie, content)

        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Elapsed time: {elapsed_time:.2f} seconds")

        info = {
            "file": nmap_file,
            "cves": cves,
            "name": file_name,
            "categories": categorie,
            "classification": classification,
        }

        nmap_info.append(info)

    return nmap_info, scripts_with_no_CVE
