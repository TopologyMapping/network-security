from kneed import KneeLocator
from pathlib import Path
import numpy as np

BASE_PATH = Path(__file__).parent / "word_list"
INPUT_FILE = BASE_PATH / 'unique_classified_words.txt'

unique_classified_list = []
with INPUT_FILE.open('r') as f:
    for line in f:
        word, frequency = line.strip().split(',')
        unique_classified_list.append((word, int(frequency)))

words, frequency = zip(*unique_classified_list)

frequency = np.array(frequency)

y = np.cumsum(frequency)
x = np.arange(1, len(y) + 1)

knee = KneeLocator(x, y)

words_knee = list(words)[:knee.knee]

REMOVED_FILE = Path(__file__).parent / 'data/removed-words.txt'
with REMOVED_FILE.open('r') as f:
    removed_words = f.read().splitlines()

new_word_list = set(words_knee) - set(removed_words)

PRESEED_FILE = Path(__file__).parent / 'data/dns-initial-keywords.txt'
with PRESEED_FILE.open('r') as f:
    preseed_words = f.read().splitlines()

aux_list = new_word_list.copy()
for preseed in preseed_words:
    for word in new_word_list:
        if preseed in word:
            aux_list.remove(word)

final_words = set(set(preseed_words) | set(aux_list))

OUTPUT_FILE = BASE_PATH / 'final_words.txt'
with OUTPUT_FILE.open('w') as f:
    f.writelines(word + '\n' for word in final_words)
