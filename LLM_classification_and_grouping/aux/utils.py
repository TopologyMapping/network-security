import dataclasses
import os

# class to organize results from classification
@dataclasses.dataclass
class ScriptClassificationResult:
    scripts_with_cves: list[str]
    scripts_without_cves: list[str]

# Try to read file with different encodings
def read_file_with_fallback(file_path):

    if not os.path.exists(file_path):
        print(file_path)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        with open(file_path, "r", encoding="iso-8859-1") as f:
            return f.read()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None
