# Needed for analysis
import os
import bz2
import json
import datetime as dt
import numpy as np
import zipfile
from itertools import repeat
from collections import defaultdict

from bs4 import BeautifulSoup
from bs4.element import Comment

# import tensorflow as tf
# import tensorflow_text as tft

from transformers import pipeline
from easynmt import EasyNMT # Translation

# Code quality
import pickle
import logging
import argparse

# Code consistency
from typing import Any, Callable, Optional

# Candidate labels
LABELS: list[str] = ["healthcare", "government", "store", "research", "education", "bank", "security", "military", "cloud computing", "internet service provider"]

VULN_LABELS: list[str] = ["remote code execution", "denial of service", "cross site scripting", "information disclosure", "sql injection", "privilege escalation", "buffer overflow", "cross site request forgery"]

# FIELD MUST BE A STRING LIKE: "field1.field2.field3" E.G.: "isakmp.flags.encryption"
def getNestedFieldData(scan: dict[str, Any], field: str) -> Any | None:
    data = scan

    # Iteratively traverse parent -> child to get desired field
    for key in field.split("."):
        data = data.get(key)

        if data == None:
            return None

    return data

def readSampleShodanFiles(folderpath: str) -> list[dict[str, Any]]:
    allData: list[dict[str, Any]] = list()

    for file in os.scandir(folderpath):
        debug_limit = 10000

        # Skip dirs and non-json files
        if not file.is_file() or not file.path.endswith((".json", ".json.bz2")):
            continue

        isFileCompressed: bool = file.path.endswith(".json.bz2")

        if isFileCompressed:
            data = bz2.open(file.path, "rt")
        else:
            data = json.load(open(file.path, "rb"))

        for scan in data:
            if debug_limit == 0:
                break

            if isFileCompressed:
                scan: dict[Any, Any] = json.loads(scan)

            allData.append(scan)

            debug_limit -= 1

        #break # For testing purposes

    return allData

def processCvesFromMitre(filepath: str, classifier: Callable, translator: Callable) -> dict[str, tuple[str, dict[str, float]]]:
    seenCves: dict[str, tuple[str, dict[str, float]]] = dict()

    with zipfile.ZipFile(filepath, "r") as file:
        cveFilename: list[str] = file.namelist()

        for idx, cveFile in enumerate(cveFilename):
            print(f"{idx + 1}/{len(cveFilename)}\r", end="")

            if not cveFile.endswith(".json"):
                continue

            with file.open(cveFile) as f:
                data: dict[str, Any] = json.loads(f.read())

                print(json.dumps(data, indent=4))
                exit()

                try:
                    state: str = data["cveMetadata"]["state"]
                except:
                    continue

                if state == "REJECTED":
                    continue

                summary: str = data["containers"]["cna"]["descriptions"][0]["value"]
                id: str = data["cveMetadata"]["cveId"]

                if id in seenCves:
                    continue

                result: dict[str, Any] = classifyZeroShotCVE(classifier, translator, summary)

                # Save to seen
                seenCves[id] = (summary, {l: s for l, s in zip(result["labels"], result["scores"])})

    return seenCves

def processOrgClassification(filepath: str, classifier: Callable, translator: Callable) -> dict[str, tuple[str, str, str, str, dict[str, float]]]:
    seenOrgs: dict[str, tuple[str, str, str, str, dict[str, float]]] = dict()

    isFileCompressed: bool = filepath.endswith(".json.bz2")

    if isFileCompressed:
        data = bz2.open(filepath, "rt")
    else:
        data = json.load(open(filepath, "rb"))

    for idx, scan in enumerate(data):
        print(f"{idx + 1}\r", end="")

        if isFileCompressed:
            scan: dict[Any, Any] = json.loads(scan)

        # Skip non http scans
        module: str | None = getNestedFieldData(scan, "_shodan.module")

        if not module or "http".casefold() not in module.casefold():
            continue

        # Get main data
        html: str | None = getNestedFieldData(scan, "http.html")
        status: int | None = getNestedFieldData(scan, "http.status")
        ip: str | None = getNestedFieldData(scan, "ip_str")
        webpageTitle: str  | None = getNestedFieldData(scan, "http.title")
        org: str | None = getNestedFieldData(scan, "org")

        if html is None or status != 200:
            continue

        # Get most common words
        sortedWords: list[str] = buildBagOfWords(html)

        if not sortedWords:
            continue

        if ip in seenOrgs:
            continue

        result: dict[str, Any] = classifyZeroShot(classifier, translator, sortedWords[:20], scan)

        # Save to seen
        seenOrgs[ip] = (ip, html, webpageTitle, org, {l: s for l, s in zip(result["labels"], result["scores"])})

    return seenOrgs

def isElementVisible(element):
    if element.parent.name in ['style', 'script', 'meta', '[document]', 'head', 'title',]:
        return False

    if isinstance(element, Comment):
        return False

    return True

def extractTextFromHtml(body: str):
    soup = BeautifulSoup(body, 'html.parser')
    # texts = soup.get_text(separator="\n", strip=True)
    texts = soup.find_all(string=True)

    visibleTexts = filter(isElementVisible, texts)

    return u"\n".join(t.strip() for t in visibleTexts)

def buildBagOfWords(html: str) -> list[str]:
    allText: str = extractTextFromHtml(html)

    bow: dict[str, Any] = defaultdict(int)

    tokens: list[str] = allText.split("\n")

    for word in tokens:
        word = word.strip()

        if len(word) < 5:
            continue

        if word.isspace():
            continue

        if not word.replace(" ", "").isalpha():
            continue

        bow[word] += 1

    # Sort words
    sortedWords: list[str] = sorted(bow, key=bow.get, reverse=True)

    return sortedWords

def classifyZeroShot(classifier, translator, sortedWords: list[str], scan: dict[str, Any]) -> dict[str, Any]:
    THRESHOLD = 0.3

    # Translate to PT, EN text is left untouched
    sortedWordsEn = translator.translate(sortedWords[:15], source_lang='pt', target_lang='en')

    # Get sequence to classify, will join using ; because sentences are not necessarily connected
    sequence = f"{'; '.join(w for w in sortedWordsEn)}"
    hypothesis = "This list of sequences is from a {} webpage."

    result = classifier(sequences=sequence, candidate_labels=LABELS, hypothesis_template=hypothesis, multi_label=False)

    # If top category has a score smaller than 0.2, we can use other data from the scan to try to get a better result
    if result["scores"][0] > THRESHOLD:
        return result

    # Get more data
    hostnames: list[str] | None = getNestedFieldData(scan, "hostnames")
    webpageTitle: str  | None = getNestedFieldData(scan, "http.title")
    org: str | None = getNestedFieldData(scan, "org")

    # Hostnames are EN by default, so translate the rest
    if webpageTitle:
        webpageTitle = translator.translate(webpageTitle.strip(), source_lang='pt', target_lang='en')

    if org:
        org = translator.translate(org.strip(), source_lang='pt', target_lang='en')

    # Try with title and organization
    if webpageTitle or org:
        sequence = f"{webpageTitle}; {org}"
        hypothesis = "This webpage title is from a {} webpage."

        result = classifier(sequences=sequence, candidate_labels=LABELS, hypothesis_template=hypothesis, multi_label=False)

        if result["scores"][0] > THRESHOLD or not hostnames:
            return result

    # Last try with hostnames
    if hostnames:
        sequence = f"; ".join(h for h in hostnames)
        hypothesis = "These hostnames are from a {} webpage."

        result = classifier(sequences=sequence, candidate_labels=LABELS, hypothesis_template=hypothesis, multi_label=False)

        return result

    # No extra data processed, return the original result anyways
    return result

def classifyZeroShotCVE(classifier, translator, vulnSummary: str) -> dict[str, Any]:
    # Summary is already in EN

    # Get sequence to classify, will join using
    sequence = f"{vulnSummary}"
    hypothesis = "This summary is from a {} vulnerability."

    result = classifier(sequences=sequence, candidate_labels=VULN_LABELS, hypothesis_template=hypothesis, multi_label=False)

    return result

if __name__ == "__main__":
    # import tensorflow as tf
    # print(tf.config.list_physical_devices('GPU'))
    # exit()

    classifier = pipeline("zero-shot-classification", model="MoritzLaurer/deberta-v3-large-zeroshot-v2.0", batch_size=16, device='cpu', fp16=True) # large or base
    translator = EasyNMT('m2m_100_418M', batch_size=8, device='cpu')

    # orgsResult = processOrgClassification("/scratch/gabriel.cardoso/datasets/BR.20240720.json.bz2", classifier, translator)

    # pickle.dump(orgsResult, open("orgsResult.pkl", "wb"))

    # exit()

    cvesResult = processCvesFromMitre("cvelistV5-main.zip", classifier, translator)
    
    pickle.dump(cvesResult, open("cvesResult.pkl", "wb"))

    exit()