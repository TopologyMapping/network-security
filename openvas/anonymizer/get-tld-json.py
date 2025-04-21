#!/usr/bin/env python3

import json
import requests
from bs4 import BeautifulSoup

IANADB = "https://www.iana.org/domains/root/db"

response = requests.get(IANADB)
if response.status_code != 200:
    print(f"Failed to download IANA DB. Status code: {response.status_code}")
    exit(1)

soup = BeautifulSoup(response.text, "html.parser")
table = soup.find("table", id="tld-table")

tld_data = []
for row in table.tbody.find_all("tr"):
    columns = row.find_all("td")
    domain = columns[0].text.strip()
    tld_type = columns[1].text.strip()
    tld_manager = columns[2].text.strip()
    tld_data.append({
        "domain": domain,
        "type": tld_type,
        "manager": tld_manager
    })

with open("tlds.json", "w") as jsonfile:
    json.dump(tld_data, jsonfile, indent=4)

print("TLD data written to tlds.json")
