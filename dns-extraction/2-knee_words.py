import pickle as pkl
from kneed import KneeLocator
from pathlib import Path
import numpy as np

base_path = Path(__file__).parent / "word_list"
input_file = base_path / 'wordlist_wonumber.pkl'

with input_file.open('rb') as f:
    word_dict = pkl.load(f)

num_words = len(word_dict)
frequency_words = sum(word_dict.values())

values = np.array(list(word_dict.values()))
y = np.cumsum(values) / values.sum()

x = np.arange(1, len(y) + 1)
knee = KneeLocator(x, y)

print(f"Knee Position in the Array : {knee.knee}")
words_knee = list(word_dict)[:knee.knee]
frequency_knee = sum(word_dict[item] for item in words_knee)
print(f"Frequency of words in rapid7 database : {frequency_knee / frequency_words * 100:.3f}")
print('Saving words up to the knee in a txt file to be used in LLM...')

output_file = base_path / 'wordlist_to_llm.txt'
with output_file.open('w') as f:
    f.writelines(word + '\n' for word in words_knee)
