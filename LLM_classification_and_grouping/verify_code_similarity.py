import argparse
import json
import random
import re
import time

from aux.llm import LLMHandler
from aux.utils import read_file_with_fallback

COMPARE_FILES_MAYBE_SIMILARS = "maybe_similars"
COMPARE_FILES_SIMILARS = "similars"
DEFAULT_NUMBER_OF_FILES_COMPARED = 500
PATTERN_ANSWER1 = re.compile(r"Answer1:\s*(.+?)\s*(?=Answer2:|$)")


def receive_arguments():

    parser = argparse.ArgumentParser(
        description="""
        This code verifies the similarity between Openvas files using LLM.
        The main objective is to verify if the files that were clasified as 'similars' and 'maybe_similars' are related to the main file or not.
        This module is not useful to be used alone, but is important to use it after calling the function 'compare_similarity_openvas' in the file 'openvas.py' to evaluate the results.
        """
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Input JSON file with similars and maybe_similars groups.",
    )
    parser.add_argument("--ip_port", required=True, help="LLM ip and port.")
    parser.add_argument(
        "--number_of_files_compared",
        type=int,
        help="Number of files to compare [%(default)s]",
        default=DEFAULT_NUMBER_OF_FILES_COMPARED,
        required=True,
    )

    return parser.parse_args()


def select_cve_to_analyze(
    number_of_files_compared: int, cves_unique_files: list, info_op_nvts: dict, key: str
):
    """
    This functions selects a random CVE to be analyzed. The selected CVE must be in the list of unique files and in the list of files to be analyzed, so its possible to compare the files.
    """

    cves = set(cves_unique_files) & set(info_op_nvts[key])
    filtered_cves = [
        cve for cve in cves if cve.startswith("CVE")
    ]  # avoiding elements with no CVE
    return random.sample(filtered_cves, number_of_files_compared)


def get_similarity_classification_info(result: str):
    """
    This functions extracts the answer and the explanation from the result of the classification.
    """

    match = PATTERN_ANSWER1.search(result)
    answer = match.group(1) if match else ""

    answer = answer.replace("[", "").replace("]", "").strip().lower()

    explanation = result.split("Answer2:")[-1].replace("[", "").replace("]", "").strip()

    return answer, explanation


def select_random_files_to_analyze(cve: str, info_op_nvts: dict, key: str):
    """
    This functions selects two random files to be compared. The first file is a unique file and the second file is a file from one of the categories to be compared (key = could be 'maybe_similars' or 'similars').
    """

    unique_file = random.choice(info_op_nvts["main_files"][cve])
    file_to_compare = random.choice(info_op_nvts[key][cve])

    return unique_file, file_to_compare


def init_classification(file1, file2, llm):

    start_time = time.time()
    result = llm.classification_code_similarity(file1, file2)
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Time elapsed: {elapsed_time:.2f} seconds")
    print()

    return result


def compare_files_and_store_results(
    info_op_nvts: dict, category_to_compare: str, number_of_files_compared: int, llm
):
    """
    This functions realizes all the steps to compare the files and store the results. The files to be compared are selected, then classified, the answer analyzed and the results stored in a json file.

    * The results are stored inside the folder 'results' in the root of the project.
        - Main Files: First files for each CVE
        - Similar Files: Files with high similarity with 'main files'
        - Maybe Similar files: Files with lower similarity with 'main files', but also good chances of being similar
    """

    results = {}
    results["yes"] = 0
    results["no"] = 0
    results["errors"] = []

    cves_main_files: list = list(info_op_nvts["main_files"].keys())

    cves_selected = select_cve_to_analyze(
        number_of_files_compared, cves_main_files, info_op_nvts, category_to_compare
    )

    for cve in cves_selected:

        unique_file_selected, file_to_compare = select_random_files_to_analyze(
            cve, info_op_nvts, category_to_compare
        )

        file1 = read_file_with_fallback(unique_file_selected)
        file2 = read_file_with_fallback(file_to_compare)

        result = init_classification(file1, file2, llm)

        answer, explanation = get_similarity_classification_info(result)

        # check if the answer is valid
        if answer != "yes" and answer != "no":
            results["errors"].append(
                f"Unique file: {unique_file_selected}, {category_to_compare} file: {file_to_compare}, Answer: {answer}, Explanation: {explanation}"
            )
            continue

        # the dictionary key is the two files compared
        classification_key = unique_file_selected + " and " + file_to_compare
        results[classification_key] = (answer, explanation)

        results[answer] += 1

    with open(
        f"./results/verify_simil_openvas__similars_{category_to_compare}.json", "w"
    ) as json_file:
        json.dump(results, json_file, indent=4)


def main():

    args = receive_arguments()

    llm = LLMHandler(args.ip_port)

    with open(args.input, "r") as file:
        info_op_nvts: dict = json.load(file)

    compare_files_and_store_results(
        info_op_nvts, COMPARE_FILES_MAYBE_SIMILARS, args.number_of_files_compared, llm
    )

    compare_files_and_store_results(
        info_op_nvts, COMPARE_FILES_SIMILARS, args.number_of_files_compared, llm
    )


if __name__ == "__main__":

    main()
