import json
import random
from faker import Faker

fake = Faker()

severity_score = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}

def generate_ip_info(ip):
    vulnerabilities = [
        {
            "CVE": f"CVE-{fake.year()}-{random.randint(1000, 9999)}",
            "Severity": random.choice(["Low", "Medium", "High", "Critical"])
        } for _ in range(random.randint(1, 5))
    ]

    score = sum(severity_score[vuln["Severity"]] for vuln in vulnerabilities)

    if len(vulnerabilities) > 3:
        vote = 2
    elif len(vulnerabilities) == 1:
        vote = 1
    else:
        vote = 0

    return {
        "IP": ip,
        "Location": fake.city(),
        "ISP": fake.company(),
        "LastSeen": fake.date_time_this_year().isoformat(),
        "Vulnerabilities": vulnerabilities,
        "Score": score,
        "Vote": vote
    }

ip_list = [fake.ipv4() for _ in range(1000)]

ip_data = [generate_ip_info(ip) for ip in ip_list]

with open('ip_data.json', 'w') as json_file:
    json.dump(ip_data, json_file, indent=4)

print("JSON data generated and saved to ip_data.json")
