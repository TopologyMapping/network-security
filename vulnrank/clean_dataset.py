import pickle
import json

from settings import(
    RISK_CLASS_GT,
    RISK_CLASS_RESIDENTES,
    RISK_NUM_RESIDENTES,
    JSON_USERS_TO_EMAIL,
)

with open(RISK_CLASS_GT, 'rb') as f:
    class_gt = pickle.load(f)

with open(RISK_CLASS_RESIDENTES, 'rb') as f:
    class_residentes = pickle.load(f)

with open(RISK_NUM_RESIDENTES, 'rb') as f:
    num_residentes = pickle.load(f)

with open(JSON_USERS_TO_EMAIL, 'r') as f:
    users_to_email = json.load(f)


class_users_gt = set(item["user_id"] for item in class_gt)
class_users_residentes = set(item["user_id"] for item in class_residentes)
num_users_residentes = set(item["user_id"] for item in num_residentes)


for item in class_users_gt:
    if "vote_class" in item:
        item["risk_class"] = item.pop("vote_class")
    if "user_id" in item:
        item["email"] = users_to_email["crivo_dev"][str(item["user_id"])]
for item in class_users_residentes:
    if "vote_class" in item:
        item["risk_class"] = item.pop("vote_class")
    if "user_id" in item:
        item["email"] = users_to_email["crivo_class"][str(item["user_id"])]
for item in num_users_residentes:
    if "vote_num" in item:
        item["risk_num"] = item.pop("vote_num")
    if "user_id" in item:
        item["email"] = users_to_email["crivo_num"][str(item["user_id"])]

# Save the updated data back to the pickle files
with open(RISK_CLASS_GT, "wb") as f:
    pickle.dump(class_users_gt, f)
with open(RISK_CLASS_RESIDENTES, "wb") as f:
    pickle.dump(class_users_residentes, f)
with open(RISK_NUM_RESIDENTES, "wb") as f:
    pickle.dump(num_users_residentes, f)
