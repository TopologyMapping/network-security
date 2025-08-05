from pathlib import Path
import tarfile
import json
import regex as re
import pickle as pkl

base_path = Path(__file__).parent / "word_list"
tar_file = base_path / 'relevant_words.tar'

json_data_list = []

with tarfile.open(tar_file, 'r') as tar:
    for member in tar.getmembers():
        if member.isfile():
            try:
                f = tar.extractfile(member)
                if f is not None:
                    data = json.load(f)
                    json_data_list.extend(data)
            except json.JSONDecodeError as e:
                pass

classes_word_dict = {}
for i in json_data_list:
    word = i['term'].lower()
    classified = i['class']
    if classified in classes_word_dict:
        classes_word_dict[classified].append(word)
    else:
        classes_word_dict[classified] = [word]

for i in list(classes_word_dict):
    if len(classes_word_dict[i]) < 100:
        del classes_word_dict[i]

word_classes_list = []
for i, words in classes_word_dict.items():
    for word in words:
        new_word = re.sub(r'\d+', '', word).strip()
        if len(new_word) > 2:
            word_classes_list.append(new_word)

word_classes_list = list(set(word_classes_list))

input_file = base_path / 'wordlist_wonumber.pkl'
with input_file.open('rb') as f:
    word_dict = pkl.load(f)

word_classes_list = [(item, word_dict[item]) for item in word_classes_list if item in word_dict]
word_classes_list = sorted(word_classes_list, key=lambda x: x[1], reverse=True)[1:] # removing "net"

output_file = base_path / 'unique_classified_words.txt'

with output_file.open('w') as f:
    for i, j in word_classes_list:
        f.write(f'{i},{j}\n')