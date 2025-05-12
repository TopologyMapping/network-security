import json
import pickle

def main():
    with open('result_id_to_crivos.json', 'r') as file:
        data = json.load(file)
    # format of JSON:
    # [
    # {"result_id": "215fc1f6-2a40-45d8-be2e-802e9c6c58dc", "crivo_dev_id": 287, "crivo_class_id": 16, "crivo_num_id": 16},
    # {"result_id": "624995db-55f3-4244-b5a1-7f5a9a6dda4b", "crivo_dev_id": 288, "crivo_class_id": 17, "crivo_num_id": 17},
    # {"result_id": "23ace4d9-7eae-4eb7-89b4-f2965645f7ad", "crivo_dev_id": 289, "crivo_class_id": 6, "crivo_num_id": null},

    with open('crivo_dev_votes.pickle', 'rb') as pickle_file:
        crivo_dev_votes = pickle.load(pickle_file)

    # format of votes:
    # [
    # {'email': 'paula.braz86@gmail.com',
    # 'id': 31,
    # 'timestamp': '2025-04-30T00:50:07.485767+00:00',
    # 'user_id': 12,
    # 'vote_class': 'Moderate'},

    dev2class = {entry['crivo_dev_id']: entry['crivo_class_id'] for entry in data}

    crivo_dev_votes = [v for v in crivo_dev_votes if v['id'] in dev2class]
    for vote in crivo_dev_votes:
        vote['id'] = dev2class[vote['id']]

    with open('crivo_class_votes.pickle', 'rb') as pickle_file:
        crivo_class_votes = pickle.load(pickle_file)

    joined_votes = crivo_dev_votes + crivo_class_votes

    with open('joined_class_votes.pickle', 'wb') as output_file:
        pickle.dump(joined_votes, output_file)


if __name__ == "__main__":
    main()
