import re
import time
import os
from utils import read_file_with_fallback, classification_text_generation
from constants import (
    PROMPT_NUCLEI,
    PROMPT_NUCLEI_REMOTE_CODE_EXECUTION,
    PROMPT_NUCLEI_AUTH_BYPASS,
)


def extract_cve_nuclei(content):

    cve_regex = re.compile(r"cve-id:\s*(CVE-[\d-]+)")
    cves = cve_regex.findall(content)

    return cves if cves else ""


def extract_nuclei_id(content):
    id_regex = re.compile(r"id:\s*([\w\-]+)")
    match = id_regex.search(content)
    return match.group(1) if match else ""


def extract_nuclei_tags(content):
    tags_regex = re.compile(r"tags:\s*([\w,\-]+)")
    match = tags_regex.search(content)
    return match.group(1).split(",") if match else []


def classification_nuclei(tags, content):

    if "rce" in tags or "sqli" in tags or "xss" in tags or "injection" in tags:

        classification = classification_text_generation(
            content, PROMPT_NUCLEI_REMOTE_CODE_EXECUTION
        )

        category_remote_code_exec = """ 

        How the script works?
        Category: {Simulated Attack}
        Subcategory: {External Code Execution}

        """

        classification += category_remote_code_exec

    elif "auth-bypass" in tags or "unauth" in tags or "default-login" in tags:

        classification = classification_text_generation(
            content, PROMPT_NUCLEI_AUTH_BYPASS
        )

        category_auth_bypass = """ 

        How the script works?
        Category: {Simulated Attack}
        Subcategory: {Unauthorized Login}

        """

        classification += category_auth_bypass
    else:
        classification = classification_text_generation(content, PROMPT_NUCLEI)

    return classification


def analysis_nuclei_templates(nuclei_folder, initial_range, final_range):

    templates_with_no_CVE = []

    nuclei_info = []

    nuclei_files = [
        os.path.join(root, file)
        for root, _, files in os.walk(nuclei_folder)
        for file in files
        if file.endswith(".yaml")
    ]

    print("Len nuclei files ", len(nuclei_files))

    for nuclei_file in nuclei_files[initial_range:final_range]:

        content = read_file_with_fallback(nuclei_file)

        cves = extract_cve_nuclei(content)

        if not (cves):

            templates_with_no_CVE.append(nuclei_file)

        id = extract_nuclei_id(content)

        tags = extract_nuclei_tags(content)

        start_time = time.time()

        classification = classification_nuclei(tags, content)

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
