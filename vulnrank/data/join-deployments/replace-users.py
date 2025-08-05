import json
import pickle


def main():
    with open("users.json", "r", encoding="utf8") as file:
        exp2user2email = json.load(file)

    for exp in exp2user2email:
        print(exp)
        with open(f"{exp}_votes.pickle", "rb") as pickle_file:
            votes = pickle.load(pickle_file)

        for vote in votes:
            user = str(vote.get("user_id"))
            if str(user) in exp2user2email[exp]:
                vote["email"] = exp2user2email[exp].get(user, "unknown")

        with open(f"{exp}_votes.pickle", "wb") as pickle_file:
            pickle.dump(votes, pickle_file)


if __name__ == "__main__":
    main()
