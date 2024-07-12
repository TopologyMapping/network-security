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

organization_types = [
    {"type": "Technology Company", "importance": 400},
    {"type": "Financial Institution", "importance": 500},
    {"type": "Healthcare Provider", "importance": 500},
    {"type": "Educational Institution", "importance": 400},
    {"type": "Retailer", "importance": 200},
    {"type": "Manufacturing Company", "importance": 300},
    {"type": "Telecommunications", "importance": 400},
    {"type": "Transportation", "importance": 300},
    {"type": "Energy Company", "importance": 500},
    {"type": "Government Agency", "importance": 500}
]

def generate_ip_info(ip, org_type, org_importance):
    vulnerabilities = [
        {
            "CVE": f"CVE-{fake.year()}-{random.randint(1000, 9999)}",
            "Severity": random.choice(["Low", "Medium", "High", "Critical"])
        } for _ in range(random.randint(1, 5))
    ]

    score = sum(severity_score[vuln["Severity"]] for vuln in vulnerabilities)

    return {
        "IP": ip,
        "Location": fake.city(),
        "ISP": fake.company(),
        "LastSeen": fake.date_time_this_year().isoformat(),
        "Vulnerabilities": vulnerabilities,
        "Score": score,
        "OrganizationType": org_type,
        "Importance": org_importance
    }

def determine_vote(vulnerabilities, importance):

    if random.random() < 0.15:
        return random.choice([0, 1, 2])

    total_severity = sum(severity_score[vuln["Severity"]] for vuln in vulnerabilities)
    adjusted_severity = total_severity * importance

    if adjusted_severity > 5000:
        return 2 
    elif adjusted_severity > 2500:
        return 1  
    else:
        return 0  

organization_data = []
for org in organization_types:
    num_ips = random.randint(5, 1000)
    ip_list = [fake.ipv4() for _ in range(num_ips)]
    ip_infos = [generate_ip_info(ip, org["type"], org["importance"]) for ip in ip_list]
    
    for ip_info in ip_infos:
        vote = determine_vote(ip_info["Vulnerabilities"], ip_info["Importance"])
        ip_info["Vote"] = vote
    
    organization_data.extend(ip_infos) 

with open('organization_type_ip_data_rand.json', 'w') as json_file:
    json.dump(organization_data, json_file, indent=4)

print("JSON data generated and saved to organization_type_ip_data.json")
