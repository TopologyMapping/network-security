import argparse
import dataclasses
import json
import os
from typing import Callable, Dict, List

from aux.metasploit import analysis_metasploit_modules
from aux.nmap import analysis_nmap_scripts
from aux.nuclei import analysis_nuclei_templates
from aux.openvas import analysis_openvas_NVTS
from aux.utils import ScriptClassificationResult


# class to handle calling the classification functions from each tool
@dataclasses.dataclass
class ToolSpec:
    name: str
    handler: Callable[[os.PathLike, int, int, str], ScriptClassificationResult]


CLASSIFICATION_RESULTS_FOLDER = "./classification"


def receive_arguments():
    parser = argparse.ArgumentParser(
        description="Match CVEs between Nmap, OpenVAS, and Nuclei templates. Store the results in a JSON file."
    )

    required_group = parser.add_argument_group(
        "Required arguments", "At least one of these must be provided."
    )
    required_group.add_argument(
        "--nmap", required=False, help="Path to the Nmap directory."
    )
    required_group.add_argument(
        "--openvas", required=False, help="Path to the OpenVAS directory."
    )
    required_group.add_argument(
        "--nuclei", required=False, help="Path to the Nuclei templates directory."
    )
    required_group.add_argument(
        "--metasploit",
        required=False,
        help="Path to the metasploit templates directory.",
    )

    parser.add_argument(
        "--initial_range", type=int, required=True, help="Initial classification range."
    )
    parser.add_argument(
        "--final_range", type=int, required=True, help="Final classification range."
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON file name.",
    )
    parser.add_argument("--ip_port", required=True, help="LLM IP and port.")

    return parser.parse_args()


def classify_scripts(
    tool_specs: List[ToolSpec], args
) -> Dict[str, Dict[str, List[str]]]:
    """
    This function processes the classification of scripts for each specified tool.
    The output is divided into scripts with CVEs and scripts without CVEs.
    """
    results = {}
    all_scripts_without_cves = []

    for tool_spec in tool_specs:
        tool_path = getattr(args, tool_spec.name)
        if tool_path:
            result = tool_spec.handler(
                tool_path, args.initial_range, args.final_range, args.ip_port
            )
            results[tool_spec.name] = {
                "scripts_with_cves": result.scripts_with_cves,
                "scripts_without_cves": result.scripts_without_cves,
            }
            all_scripts_without_cves.extend(result.scripts_without_cves)

    return results


if __name__ == "__main__":
    args = receive_arguments()

    tool_specs = [
        ToolSpec("nmap", analysis_nmap_scripts),
        ToolSpec("metasploit", analysis_metasploit_modules),
        ToolSpec("nuclei", analysis_nuclei_templates),
        ToolSpec("openvas", analysis_openvas_NVTS),
    ]

    classification_results = classify_scripts(tool_specs, args)

    os.makedirs(CLASSIFICATION_RESULTS_FOLDER, exist_ok=True)
    output_file = os.path.join(
        CLASSIFICATION_RESULTS_FOLDER, f"{args.output}_classification.json"
    )

    with open(output_file, "w") as f:
        json.dump(classification_results, f, indent=4)
