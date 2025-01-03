"""
This module provides functionality for classifying Nuclei scripts.

The classification process involves:
1. Analyzing the content of each script and extracting metadata using regular expressions.
2. Sending the extracted information to a language model (LLM) with a specific prompt for classification.
3. Organizing the scripts into appropriate categories based on the LLM's responses.

The classification is performed in batches to efficiently handle large numbers of files.
"""

import dataclasses
import os
import time

import yaml
from dataclasses_json import dataclass_json

from .constants import (
    PROMPT_NUCLEI,
    PROMPT_NUCLEI_AUTH_BYPASS,
    PROMPT_NUCLEI_REMOTE_CODE_EXECUTION,
)
from .llm import LLMHandler
from .utils import ScriptClassificationResult, read_file_with_fallback

FILE_EXTENSION_NUCLEI = ".yaml"

REMOTE_CODE_EXECUTION_TAGS: set = {"rce", "sqli", "xss", "injection"}
AUTH_BYPASS_TAGS: set = {"auth-bypass", "unauth", "default-login"}


# class to organize information about the Nuclei script
@dataclass_json
@dataclasses.dataclass
class NucleiTemplateInfo:
    file: str
    cves: list[str]
    id: str
    classification: str


# get information from the Nuclei YAML file
def parse_nuclei_yaml(content) -> dict:
    """
    Parse YAML content into a Python dictionary.
    """
    try:
        return yaml.safe_load(content)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML content: {e}")
        return {}


def extract_cve_nuclei(yaml_data: dict) -> list:
    try:
        return yaml_data["info"]["classification"][
            "cve-id"
        ]  # nuclei structure to get cve-id
    except:
        return []


def extract_nuclei_id(yaml_data: dict) -> str:
    return yaml_data.get("id", "")


def extract_nuclei_tags(yaml_data: dict) -> list:
    try:
        str_tags = yaml_data["info"]["tags"]  # nuclei structure to get tags
        return str_tags.split(",")
    except:
        return []


def classification_nuclei(tags: list, content, llm) -> str:
    """
    This function filters the content of the Nuclei script and classifies it according to the tags collected.
    """
    classification: str = ""

    if REMOTE_CODE_EXECUTION_TAGS.intersection(tags):

        classification = llm.classification_text_generation(
            content, PROMPT_NUCLEI_REMOTE_CODE_EXECUTION
        )

        category_remote_code_exec = """ 

        How the script works?
        Category: {Simulated Attack}
        Subcategory: {External Code Execution}

        """

        classification += category_remote_code_exec

    elif AUTH_BYPASS_TAGS.intersection(tags):

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


def analysis_nuclei_templates(
    nuclei_folder: str, initial_range: int, final_range: int, ip_port: str
) -> ScriptClassificationResult:
    """
    How the function works:
        This file handles the classification of Nuclei scripts. Useful information is taken from the file metadata to perform the classification, and then sent to the LLM that will perform the task.

        Since there are many files to be classified, the function operates in batches, classifying files in a given range of values.

    Input: Folder with Nuclei templates and range for classification.

    Output: classified files and information about files without CVE.
    """

    llm = LLMHandler(ip_port)

    templates_with_no_CVE: list = []

    nuclei_info: list = []

    nuclei_files = [
        os.path.join(root, file)
        for root, _, files in os.walk(nuclei_folder)
        for file in files
        if file.endswith(FILE_EXTENSION_NUCLEI)
    ]

    # sorting files by name to ensure the order of classification
    nuclei_files = sorted(nuclei_files, key=lambda file: os.path.basename(file))

    print("Len nuclei files ", len(nuclei_files))

    for nuclei_file in nuclei_files[initial_range:final_range]:

        content = read_file_with_fallback(nuclei_file)
        yaml_data = parse_nuclei_yaml(content)

        id = extract_nuclei_id(yaml_data)

        if not id:
            continue

        cves = extract_cve_nuclei(yaml_data)

        if not cves:

            templates_with_no_CVE.append(nuclei_file)

        tags = extract_nuclei_tags(yaml_data)

        start_time = time.time()

        classification = classification_nuclei(tags, content, llm)

        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Elapsed time: {elapsed_time:.2f} seconds")

        info = NucleiTemplateInfo(
            file=nuclei_file,
            cves=cves,
            id=id,
            classification=classification,
        ).to_dict()

        nuclei_info.append(info)

    return ScriptClassificationResult(
        scripts_with_cves=nuclei_info, scripts_without_cves=templates_with_no_CVE
    )
