#!/usr/bin/env python3

import argparse
import bz2
import json
import logging
import os
import pickle
from collections import defaultdict
from typing import Any, Callable

import torch
from bs4 import BeautifulSoup
from bs4.element import Comment
from easynmt import EasyNMT  # Translation
from transformers import Pipeline, pipeline

# Candidate labels
LABELS: list[str] = [
    "healthcare",
    "government",
    "store",
    "research",
    "education",
    "bank",
    "security",
    "military",
    "cloud computing",
    "internet service provider",
]


def initParser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Classifies scans from Shodan into organization categories using a zero-shot classifier. \
        The result is a vector of probabilities for each category that can be used as a feature for the XGBoost model."
    )

    parser.add_argument(
        "shodanDir",
        metavar="shodan-dir",
        type=str,
        help="directory with a collection of Shodan daily scans (each as a .json or .json.bz2 file)",
    )

    parser.add_argument(
        "outFile",
        metavar="output-file",
        type=str,
        default="cve-output",
        help="path to the output file. The default format is .pickle, use a -j flag to get a .json file instead",
    )

    parser.add_argument(
        "-j",
        "--out-json",
        dest="jsonOutput",
        action="store_true",
        default=False,
        help="If enabled, the output file will be a .json file instead of .pickle. (default: %(default)s)",
    )

    parser.add_argument(
        "-f",
        "--logfile",
        type=str,
        dest="logfile",
        action="store",
        default=None,
        help="file to store log outputs. If not specified, logs will be printed on screen",
    )

    parser.add_argument(
        "-l",
        "--loglevel",
        type=str,
        dest="loglevel",
        metavar="LOGLEVEL",
        action="store",
        choices=["DEBUG", "INFO", "WARN", "ERROR", "FATAL"],
        default="INFO",
        help="log level. Available options: DEBUG, INFO, WARN, ERROR, FATAL (default: %(default)s)",
    )

    return parser


def getNestedFieldData(scan: dict[str, Any], field: str) -> Any | None:
    """
    Get data from a scan given the desired field, regardless of how nested it is.

    Parameters
    ----------
    `scan`: scan to get data from.
    `field`: nested field with data.

    Returns
    -------
    `data`: raw data from the desired field, or None if the field is not found.
    """

    data = scan

    # Iteratively traverse parent -> child to get desired field
    for key in field.split("."):
        data = data.get(key)

        if data == None:
            return None

    return data


def isElementVisible(element) -> bool:
    """
    Checks if an element is visible in the HTML.

    Parameters
    ----------
    `element`: element to check.

    Returns
    -------
    `bool`: True if the element is visible, False otherwise.
    """

    if element.parent.name in [
        "style",
        "script",
        "meta",
        "[document]",
        "head",
        "title",
    ]:
        return False

    if isinstance(element, Comment):
        return False

    return True


def extractTextFromHtml(body: str) -> list[str]:
    """
    Extracts visible text from an HTML body.

    Parameters
    ----------
    `body`: HTML body to extract text from.

    Returns
    -------
    `text`: visible text from the HTML body, as a list of sentences.
    """

    soup = BeautifulSoup(body, "html.parser")

    texts = soup.find_all(string=True)

    visibleTexts = filter(isElementVisible, texts)

    return [t.strip() for t in visibleTexts]


def buildBagOfWords(html: str) -> list[str]:
    """
    Builds a bag of words from the visible text of an HTML body.

    Separate words are counted and sorted by frequency.

    Parameters
    ----------
    `html`: HTML body to extract text from.

    Returns
    -------
    `sortedWords`: list of words sorted by frequency, from most to least frequent.
    """

    allText: list[str] = extractTextFromHtml(html)

    bow: dict[str, int] = defaultdict(int)

    for word in allText:
        if word.isspace():
            continue

        # Don't include prepositions, articles, etc
        if len(word) < 5:
            continue

        bow[word] += 1

    # Sort words
    sortedWords: list[str] = sorted(bow, key=bow.get, reverse=True)

    return sortedWords


def classifyOrganization(
    classifier: Pipeline, translator, sortedWords: list[str], scan: dict[str, Any]
) -> dict[str, Any]:
    """
    Classifies the organization of a webpage from Shodan using a zero-shot classifier.

    Only HTTP or HTTPS scans are considered. All text in the webpage is translated to English before classification.

    In order to get a good result, multiple tries are made using different data from the scan:
    - First try with the 15 most common words in the webpage.
    - If the score is too low, try with the webpage title and organization.
    - If the score is still too low, try with the hostnames.
    - Fallback to the original result if no extra data is available or if the score could not be improved.

    Parameters
    ----------
    `classifier`: zero-shot classifier model.
    `translator`: translation model.
    `sortedWords`: list of words in the webpage sorted by frequency, from most to least frequent.
    `scan`: scan data from Shodan, used to get extra data if needed.

    Returns
    -------
    `result`: dictionary with the classification result.
    """

    # Threshold to consider the classification valid
    THRESHOLD: float = 0.3

    # Translate to PT, EN text is left untouched
    sortedWordsEn: list[str] = translator.translate(
        sortedWords[:15], source_lang="pt", target_lang="en"
    )

    # Get sequence to classify, will join using ; because sentences are not necessarily connected
    sequence: str = "; ".join(w for w in sortedWordsEn)
    hypothesis: str = "This list of sequences is from a {} webpage."

    result: dict = classifier(
        sequences=sequence,
        candidate_labels=LABELS,
        hypothesis_template=hypothesis,
        multi_label=False,
    )

    # If top category has a score smaller than threshold, we can use other data from the scan to try to get a better result
    if result["scores"][0] > THRESHOLD:
        return result

    # Get more data
    hostnames: list[str] | None = getNestedFieldData(scan, "hostnames")
    webpageTitle: str | None = getNestedFieldData(scan, "http.title")
    org: str | None = getNestedFieldData(scan, "org")

    # Hostnames are EN by default, so translate the rest
    if webpageTitle:
        webpageTitle = translator.translate(
            webpageTitle.strip(), source_lang="pt", target_lang="en"
        )

    if org:
        org = translator.translate(org.strip(), source_lang="pt", target_lang="en")

    # Try with title and organization
    if webpageTitle or org:
        # Dinamically adjust prompt based on available data
        hypothesis: str = "This "
        sequence: str = ""

        if webpageTitle:
            sequence += f"Title = {webpageTitle}"
            hypothesis += "webpage title"

        if org:
            if webpageTitle:
                hypothesis += " and "

            sequence += f"; Organization = {org}"
            hypothesis += "organization"

        hypothesis += " are " if webpageTitle and org else " is "
        hypothesis += "from a {} webpage."

        result = classifier(
            sequences=sequence,
            candidate_labels=LABELS,
            hypothesis_template=hypothesis,
            multi_label=False,
        )

        if result["scores"][0] > THRESHOLD or not hostnames:
            return result

    # Last try with hostnames
    if hostnames:
        sequence = "; ".join(h for h in hostnames)
        hypothesis = "These hostnames are from a {} webpage."

        result = classifier(
            sequences=sequence,
            candidate_labels=LABELS,
            hypothesis_template=hypothesis,
            multi_label=False,
        )

        return result

    # No extra data processed, return the original result anyways
    return result


def processOrgsFromShodan(
    shodanDir: str, classifier: Pipeline, translator: Callable
) -> dict[str, dict[str, float]]:
    """
    Processes a collection of Shodan scans to classify the organization of the webpages.

    The scans with a HTTP or HTTPS webpage are classified into organization categories.

    Parameters
    ----------
    `shodanDir`: directory with a collection of Shodan daily scans (each as a .json or .json.bz2 file).
    `classifier`: zero-shot classifier model.
    `translator`: translation model

    Returns
    -------
    `result`: dictionary with the classification result.
    """

    seenOrgs: dict[str, dict[str, float]] = dict()

    for file in os.scandir(shodanDir):
        # Skip dirs and non-json files
        if not file.is_file() or not file.path.endswith((".json", ".json.bz2")):
            continue

        isFileCompressed: bool = file.path.endswith(".json.bz2")

        if isFileCompressed:
            data = bz2.open(file.path, "rt")
        else:
            data = json.load(open(file.path, "rb"))

        # Process data
        for idx, scan in enumerate(data):
            if idx % 1000 == 0:
                logging.info(f"Progress {idx + 1} / {len(data)}")

            if isFileCompressed:
                scan: dict[Any, Any] = json.loads(scan)

            # Skip non http scans
            module: str | None = getNestedFieldData(scan, "_shodan.module")

            if not module or "http".casefold() not in module.casefold():
                continue

            # Get main data
            html: str | None = getNestedFieldData(scan, "http.html")
            status: int | None = getNestedFieldData(scan, "http.status")
            shodanId: str | None = getNestedFieldData(scan, "_shodan.id")

            if html is None or status != 200:
                continue

            # Get most common words
            sortedWords: list[str] = buildBagOfWords(html)

            if not sortedWords:
                continue

            if shodanId in seenOrgs:
                continue

            result: dict[str, Any] = classifyOrganization(
                classifier, translator, sortedWords[:20], scan
            )

            # Save to seen
            seenOrgs[shodanId] = {
                l: s for l, s in zip(result["labels"], result["scores"])
            }

            # Immediate result with debug
            logging.debug(f"{shodanId}: {html} -> {seenOrgs[shodanId]}")
            logging.debug("")  # Readability

    return seenOrgs


def genOutputFile(
    filepath: str, cvesResult: dict[str, tuple[str, dict[str, float]]], jsonOutput: bool
) -> None:
    """
    Generates an output file of the desired format.

    Parameters
    ----------
    `filepath`: output file path.
    `cvesResult`: dictionary with the results of the classification.
    `jsonOutput`: if True, the output file will be a .json file, otherwise it will be a .pickle file.
    """

    if jsonOutput:
        with open(filepath, "w") as f:
            json.dump(cvesResult, f, indent=4)
    else:
        pickle.dump(cvesResult, open(filepath, "wb"))

    logging.info(f"Output file saved to {filepath}")


if __name__ == "__main__":
    # Get args
    parser = initParser()
    args = parser.parse_args()

    # Auto enable log file if log level is DEBUG
    if args.loglevel == "DEBUG" and args.logfile == None:
        args.logfile = f"classify_orgs_debug.log"
        print(
            f"A log file is required for log level DEBUG. Logs will be written to '{args.logfile}'"
        )

    # Set up log
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s: %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S %p",
        level=getattr(logging, args.loglevel),
        filename=args.logfile,
        encoding="utf-8",
    )

    device: str = "cuda" if torch.cuda.is_available() else "cpu"
    args.outFile += ".json" if args.jsonOutput else ".pickle"

    # Run summary
    logging.info(f"Using device: {device}")
    logging.info(f"Log level: {args.loglevel}")
    logging.info(f"Output file: {args.outFile}")

    # Run
    logging.info("Loading model... this may take a while on the first run")

    classifier: Pipeline = pipeline(
        "zero-shot-classification",
        model="MoritzLaurer/deberta-v3-large-zeroshot-v2.0",
        batch_size=16,
        device=device,
        fp16=True,
    )

    translator = EasyNMT("m2m_100_418M", batch_size=8, device=device)

    orgsResult: dict = processOrgsFromShodan(args.shodanDir, classifier, translator)

    genOutputFile(args.outFile, orgsResult, args.jsonOutput)
