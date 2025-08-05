from kneed import KneeLocator
from pathlib import Path
import numpy as np

base_path = Path(__file__).parent / "word_list"
input_file = base_path / 'unique_classified_words.txt'

unique_classified_list = []
with input_file.open('r') as f:
    for line in f:
        word, frequency = line.strip().split(',')
        unique_classified_list.append((word, int(frequency)))

words, frequency = zip(*unique_classified_list)

frequency = np.array(frequency)

y = np.cumsum(frequency)
x = np.arange(1, len(y) + 1)

knee = KneeLocator(x, y)

words_knee = list(words)[:knee.knee]
removed_words = ["berlin", "cli", "comcast", "comcastbusiness", "disa", "east", "edu", "eur", "exacttarget", "google", "googlefiber", "gov", "ide",
            "jax", "kpn", "lax", "linode", "localhost", "mia", "mil", "north", "nyc", "ord", "ovh", "pentagon", "primus", "ptr", "resnet", "reverse",
            "south", "spectrum", "sub", "swisscom", "syd", "telecable", "telefonica", "telekom", "telia", "toyama", "telkom", "tokyo", "turktelekom",
            "verizon", "viettel", "vodafone", "west", "wind", "yahoo", "zayo", "oraclecloud"]

new_word_list = set(words_knee) - set(removed_words)

preseed_file = Path(__file__).parent / 'dns-keywords.txt'
with preseed_file.open('r') as f:
    preseed_words = f.read().splitlines()

aux_list = new_word_list.copy()
for preseed in preseed_words:
    for word in new_word_list:
        if preseed in word:
            aux_list.remove(word)

final_words = set(set(preseed_words) | set(aux_list))

output_file = base_path / 'final_words.txt'
with output_file.open('w') as f:
    f.writelines(word + '\n' for word in final_words)