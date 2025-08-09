from collections import defaultdict
from pathlib import Path
import pickle as pkl
import sys
import argparse

parser = argparse.ArgumentParser(description="Processes wordlist_level_X.txt files from a folder")
parser.add_argument('--folder', type=str, required=True, help='Path to wordlists folder')
args = parser.parse_args()

wordlist_dir = Path(args.folder)

if not wordlist_dir.exists() or not wordlist_dir.is_dir():
    print(f"Error: The folder '{wordlist_dir}' does not exist.")
    sys.exit(1)

print("Processed files will be saved in the ./word_list folder (automatically created if it does not exist).")

word_dict = defaultdict(int)

for i in range(8):
    file_path = wordlist_dir / f'wordlist_level_{i}.txt'
    try:
        with file_path.open('r') as f:
            for line in f:
                word, count = line.strip().split(',')
                word_dict[word] += int(count)
    except FileNotFoundError:
        print(f"File {file_path} not found. Skipping.")
    except Exception as e:
        print(f"Error reading {file_path}: {e}")

for key in list(word_dict.keys()):
    if key.isdigit():
        del word_dict[key]

base_path = Path(__file__).parent / "word_list"
base_path.mkdir(parents=True, exist_ok=True)

sorted_dict = dict(sorted(word_dict.items(), key=lambda item: item[1], reverse=True))

output_file = base_path / 'wordlist_wonumber.pkl'
with output_file.open('wb') as f:
    pkl.dump(sorted_dict, f)

print(f"Wordlist saved successfully to {output_file}")
