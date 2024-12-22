import argparse
import json
import logging
import pickle
import zipfile
from typing import Any

import torch
from transformers import *

# Candidate labels
VULN_LABELS: list[str] = ["remote code execution", "denial of service", "cross site scripting", "information disclosure", "sql injection", "privilege escalation", "buffer overflow", "cross site request forgery"]

def processCvesFromMitre(filepath: str, classifier: Pipeline) -> dict[str, tuple[str, dict[str, float]]]:
    seenCves: dict[str, tuple[str, dict[str, float]]] = dict()

    with zipfile.ZipFile(filepath, "r") as file:
        # The zip file contains a folder with all the CVEs as JSON files
        cveFilename: list[str] = file.namelist()

        for idx, cveFile in enumerate(cveFilename):
            print(f"{idx + 1}/{len(cveFilename)}\r", end="")

            if not cveFile.endswith(".json"):
                continue

            with file.open(cveFile) as f:
                data: dict[str, Any] = json.loads(f.read())

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

                result: dict[str, Any] = classifyZeroShotCVE(classifier, summary)

                # Save to seen
                seenCves[id] = (summary, {l: s for l, s in zip(result["labels"], result["scores"])})

    return seenCves

def classifyZeroShotCVE(classifier: Pipeline, vulnSummary: str) -> dict[str, Any]:
    # Summary is already in EN, we don't need to translate

    # Get sequence to classify and add some context
    sequence: str = f"{vulnSummary}"
    hypothesis: str = "This summary is from a {} vulnerability."

    result: dict = classifier(sequences=sequence, candidate_labels=VULN_LABELS, hypothesis_template=hypothesis, multi_label=False)

    return result

if __name__ == "__main__":
   

    device: str = "cuda" if torch.cuda.is_available() else "cpu"

    classifier: Pipeline = pipeline("zero-shot-classification", model="MoritzLaurer/deberta-v3-large-zeroshot-v2.0", batch_size=16, device=device, fp16=True)

    cvesResult = processCvesFromMitre("C:\\Users\\Gab\\Downloads\\cvelistV5-main.zip", classifier)
    
    pickle.dump(cvesResult, open("cvesResult.pkl", "wb"))