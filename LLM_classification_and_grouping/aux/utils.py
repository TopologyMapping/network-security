import dataclasses
import os

@dataclasses.dataclass
class ScriptClassificationResult:
    scripts_with_cves: list[str]
    scripts_without_cves: list[str]

def find_key_by_value(input_dict, value):
    keys = [key for key, val in input_dict.items() if val == value]
    return keys


# Try to read file with different encodings
def read_file_with_fallback(file_path):

    if not os.path.exists(file_path):
        print(file_path)
        raise FileNotFoundError()

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        with open(file_path, "r", encoding="iso-8859-1") as f:
            return f.read()
