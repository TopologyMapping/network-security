from utils import read_file_with_fallback, classification_text_generation
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


def extract_privileged_metasploit(content):
    match = re.search(r"'Privileged'\s*=>\s*(true|false)\s*,", content, re.IGNORECASE)

    if match:
        return match.group(1)
    else:
        return None


def extract_cve_from_metasploit(metasploit_file):
    """Extract CVE identifiers from a Metasploit file."""
    # content = read_file_with_fallback(metasploit_file)
    cve_pattern = re.compile(r"\[\s*'CVE'\s*,\s*'(\d{4}-\d+)'\s*\]")
    cves = cve_pattern.findall(metasploit_file)

    for i in range(
        len(cves)
    ):  # adding word cve in cve list because the regex dont match it
        cves[i] = "CVE-" + cves[i]
    return cves


def extract_rank_from_metasploit(metasploit_file):
    """Extract rank values from a Metasploit file."""
    # content = read_file_with_fallback(metasploit_file)
    rank_pattern = re.compile(r"Rank\s*=\s*(\w*)")

    rank = rank_pattern.search(metasploit_file)

    return rank.group(1) if rank else None


def extract_module_metasploit(metasploit_file):
    """Extract module type (Auxiliary, Post, Exploit) from a Metasploit file."""
    # content = read_file_with_fallback(metasploit_file)
    module_type_pattern = re.compile(r"class\s+MetasploitModule\s+<\s*Msf::(\w+)")
    match = module_type_pattern.search(metasploit_file)
    return match.group(1) if match else None


def execute_exploit_metasploit(metasploit_file):
    # Regular expression to find 'Msf::Exploit'
    pattern = r"Msf::Exploit"

    if re.search(pattern, metasploit_file):
        return True
    else:
        return False


def extract_name_metasploit(content):
    name_regex = re.compile(r"'Name'\s*=>\s*'([^']+)'")
    match = name_regex.search(content)
    return match.group(1) if match else ""


def classification_metasploit(module, privileged, executes_exploit, content):

    classification = ""

    # based on the module information, we classify the module with the correct prompt
    if privileged == "true" and (module == "Exploit" or executes_exploit is True):
        classification = classification_text_generation(
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
        classification = classification_text_generation(content, PROMPT_METASPLOIT_POST)
    elif privileged == "true":
        classification = classification_text_generation(
            content, PROMPT_METASPLOIT_PRIVILEGED
        )
    elif module == "Exploit" or executes_exploit is True:
        classification = classification_text_generation(
            content, PROMPT_METASPLOIT_EXPLOIT
        )
    else:
        classification = classification_text_generation(
            content, PROMPT_METASPLOIT_NOT_EXPLOIT_NOT_PRIVILEGED
        )

    return classification


def analysis_metasploit_modules(metasploit_folder, initial_range, final_range):

    modules_with_no_CVE = []

    metasploit_info = []

    metasploit_files = [
        os.path.join(root, file)
        for root, _, files in os.walk(metasploit_folder)
        for file in files
        if file.endswith(".rb")
    ]

    print("Len metasploit files ", len(metasploit_files))

    for metasploit_file in metasploit_files[initial_range:final_range]:

        content = read_file_with_fallback(metasploit_file)

        cves = extract_cve_from_metasploit(content)

        if not (cves):

            modules_with_no_CVE.append(metasploit_file)
            # continue

        module = extract_module_metasploit(content)

        # skipping modules that works as 'support' to exploits, not related directly with vulnerability discovery
        if module in ["Evasion", "Payloads", "Nop", "Encoder"]:
            continue

        privileged = extract_privileged_metasploit(content)

        executes_exploit = execute_exploit_metasploit(content)

        start_time = time.time()

        # based on the module information, we classify the module with the correct prompt
        # if privileged == 'true' and (module == 'Exploit' or executes_exploit is True ):
        #    classification = classification_text_generation(content, PROMPT_METASPLOIT_EXPLOIT_PRIVILEGED)
        #
        #    # in this case, the category and subcategory are already defined
        #    category_privileged_exploit = """
        #
        #    How the script works?
        #    Category: {Simulated Attack}
        #    Subcategory: {Privileged Attack}
        #
        #    """
        #    classification += category_privileged_exploit
        #
        # elif module == 'Post':
        #    classification = classification_text_generation(content,  PROMPT_METASPLOIT_POST)
        # elif privileged == 'true':
        #    classification = classification_text_generation(content,  PROMPT_METASPLOIT_PRIVILEGED)
        # elif module == 'Exploit' or executes_exploit is True :
        #    classification = classification_text_generation(content,  PROMPT_METASPLOIT_EXPLOIT)
        # else:
        #    classification = classification_text_generation(content,  PROMPT_METASPLOIT_NOT_EXPLOIT_NOT_PRIVILEGED)

        classification = classification_metasploit(
            module, privileged, executes_exploit, content
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
