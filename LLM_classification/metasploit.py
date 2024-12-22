from utils import read_file_with_fallback
from constants import (
    PROMPT_METASPLOIT_EXPLOIT_PRIVILEGED,
    PROMPT_METASPLOIT_POST,
    PROMPT_METASPLOIT_PRIVILEGED,
    PROMPT_METASPLOIT_EXPLOIT,
    PROMPT_METASPLOIT_NOT_EXPLOIT_NOT_PRIVILEGED,
)
import os
import re
import time
from LLM import LLMHandler

"""
    This file contains the functions to classify Metasploit scripts.
    The classification is done by analyzing the content of the script, extracting metadada using regex and then sending the information to the LLM with the appropriate prompt.
    The classification is done in batches, as there are many files to be classified.
    Below, the functions are described in more detail.
"""


PRIVILEGED_REGEX = re.compile(r"'Privileged'\s*=>\s*(?P<privileged>true|false)\s*,", re.IGNORECASE)
METASPLOIT_CVE_REGEX = re.compile(r"\[\s*'CVE'\s*,\s*'(?P<cve>\d{4}-\d+)'\s*\]")
METASPLOIT_RANK_REGEX = re.compile(r"Rank\s*=\s*(?P<rank>\w*)")
METASPLOIT_MODULE_REGEX = re.compile(r"class\s+MetasploitModule\s+<\s*Msf::(?P<module>\w+)")
METASPLOIT_EXPLOIT_REGEX = re.compile(r"Msf::Exploit")
METASPLOIT_NAME_REGEX = re.compile(r"'Name'\s*=>\s*'(?P<name>[^']+)'")

# REGEX FUNCTIONS TO EXTRACT INFO
def extract_privileged_metasploit(content) -> bool:
    match = PRIVILEGED_REGEX.search(content)
    return bool(match.group("privileged")) if match else False

def extract_cve_from_metasploit(metasploit_file) -> list:
    cves = [f"CVE-{match.group('cve')}" for match in METASPLOIT_CVE_REGEX.finditer(metasploit_file)]
    return cves

def extract_rank_from_metasploit(metasploit_file) -> str:
    match = METASPLOIT_RANK_REGEX.search(metasploit_file)
    return match.group("rank") if match else ""

def extract_module_metasploit(metasploit_file) -> str:
    match = METASPLOIT_MODULE_REGEX.search(metasploit_file)
    return match.group("module") if match else ""

def execute_exploit_metasploit(metasploit_file) -> bool:
    return bool(METASPLOIT_EXPLOIT_REGEX.search(metasploit_file))

def extract_name_metasploit(content) -> str:
    match = METASPLOIT_NAME_REGEX.search(content)
    return match.group("name") if match else ""


def classification_metasploit(module: str, privileged: bool, executes_exploit: bool, content, llm) -> str:
    """
    This function filters the content of the Metasploit script and classifies it according to the module name, and execution details like if the code requires privileged information or if it is an exploit.
    """

    classification : str = ""

    # based on the module information, we classify the module with the correct prompt
    if privileged is True and (module == "Exploit" or executes_exploit is True):
        classification = llm.classification_text_generation(
            content, PROMPT_METASPLOIT_EXPLOIT_PRIVILEGED
        )

        # in this case, the category and subcategory are already defined
        category_privileged_exploit = """ 

        How the script works?
        Category: {Simulated Attack}
        Subcategory: {Privileged Attack}

        """
        classification += category_privileged_exploit

    elif module == "Post":
        classification = llm.classification_text_generation(content, PROMPT_METASPLOIT_POST)
    elif privileged is True:
        classification = llm.classification_text_generation(
            content, PROMPT_METASPLOIT_PRIVILEGED
        )
    elif module == "Exploit" or executes_exploit is True:
        classification = llm.classification_text_generation(
            content, PROMPT_METASPLOIT_EXPLOIT
        )
    else:
        classification = llm.classification_text_generation(
            content, PROMPT_METASPLOIT_NOT_EXPLOIT_NOT_PRIVILEGED
        )

    return classification


def analysis_metasploit_modules(metasploit_folder, initial_range, final_range, ip_port) -> tuple:
    """
    How the function works:
        This file handles the classification of Metasploit scripts. Useful information is taken from the file metadata to perform the classification, and then sent to the LLM that will perform the task.

        Since there are many files to be classified, the function operates in batches, classifying files in a given range of values.

    Input: Folder with Metasploit templates and range for classification.

    Output: classified files and information about files without CVE.
    """

    llm = LLMHandler(ip_port)

    modules_with_no_CVE : list = []

    metasploit_info : list = []

    metasploit_files = [
        os.path.join(root, file)
        for root, _, files in os.walk(metasploit_folder)
        for file in files
        if file.endswith(".rb")
    ]
    
    # sorting files by name to ensure the order of classification
    metasploit_files = sorted(
        metasploit_files,
        key=lambda file: os.path.basename(file)
    )

    print("Len metasploit files ", len(metasploit_files))

    for metasploit_file in metasploit_files[initial_range:final_range]:

        content = read_file_with_fallback(metasploit_file)

        cves = extract_cve_from_metasploit(content)

        if not (cves):

            modules_with_no_CVE.append(metasploit_file)

        module = extract_module_metasploit(content)

        # skipping modules that works as 'support' to exploits, not related directly with vulnerability discovery
        if module in ["Evasion", "Payloads", "Nop", "Encoder"]:
            continue

        privileged = extract_privileged_metasploit(content)

        executes_exploit = execute_exploit_metasploit(content)

        start_time = time.time()

        classification = classification_metasploit(
            module, privileged, executes_exploit, content, llm
        )


        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Elapsed time: {elapsed_time:.2f} seconds")

        info = {
            "file": metasploit_file,
            "cves": cves,
            "module": module,
            "privileged": privileged,
            "classification": classification,
        }

        metasploit_info.append(info)

    return metasploit_info, modules_with_no_CVE
