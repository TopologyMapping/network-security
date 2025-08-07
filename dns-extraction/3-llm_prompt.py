import openai
from pathlib import Path
import argparse
import ipaddress
import sys
import tarfile
import io

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

parser = argparse.ArgumentParser(description="Receives an IP and connects to Llama3")

parser.add_argument('--ip', type=str, required=True, help='Send a valid IP address to access LLAMA3 (e.g., 192.168.0.1)')
parser.add_argument('-p', '--port', type=int, default=22, help='Port number to connect (default: 22)')

args = parser.parse_args()

IP = args.ip
PORT = args.port

if not is_valid_ip(IP):
    print(f"Invalid IP address: {IP}")
    sys.exit(1)

BASE_PATH = Path(__file__).parent / "word_list"
INPUT_FILE = BASE_PATH / "wordlist_to_llm.txt"

URL = f"http://{IP}:{PORT}" # "http://192.168.62.35:50001/v1"

def split_into_blocks(file_name, block_size):
    with open(file_name, 'r', encoding='utf-8') as file:
        words = [line.strip() for line in file.readlines()]
        print(f"Total words read: {len(words)}")

    blocks = ["\n".join(words[i:i + block_size]) for i in range(0, len(words), block_size)]
    
    print(f"Total blocks created: {len(blocks)}")
    return blocks

# Suggested block size 
# Small (10-50 words): Ideal for more detailed and precise answers.
# Medium (50-200 words): Good balance between context and efficient processing. 
# Large (200-500 words): Can be useful for broader analysis, but can quickly reach the context limit. 5000 tokens + prompt (verificar tamanho da janela de contexto no HugginFace), se a janela de contexto for 5000
blocks_of_words = split_into_blocks(INPUT_FILE, 1000)  # Blocks of 1000 words

print(f"Connecting to URL : {URL}")

llm = openai.OpenAI(
    base_url=URL,
    api_key="sk-no-key-required"
)

print("Testing connection to LLM...")

try:
    llm.chat.completions.create(
        model="llama-3-70b-q6",
        messages=[{"role": "user", "content": "ping"}],
        max_tokens=1
    )
    print("Successful Connection!")
except Exception as e:
    print(e)
    sys.exit(1)

SYSTEM_PROMPT = """
You are an assistant to a security analyst.

The analyst will provide a list of *words*, one per line.

Your task is to identify *terms* that may be relevant to security analysis.
We want to identify terms that provide insight into how critical a device is:
the context where the device is deployed,
what services it is running,
how these services are implemented,
the type or amount data handled by the devices,
the type and number users of the hosted services,
how much damage compromising the device would cause, and
impact on business objectives.

A term can be a substring of a word provided by the user (one per line).
Try do identify concise terms.

There is a list of 11 *classes* of terms.
Here is the list of classes, each with several example terms for your calibration:

1. Device Types: router, switch, firewall, cgnat, gateway, wan, lan, edge, border, waf, server, nas, gw, wifi
2. Vendors: cisco, juniper, brocade, tplink, arista, mikrotik, fortinet, fortigate, paloalto, f5
3. Protocols: dns, dhcp, ntp, smtp, imap, pop, ftp, nfs, smb, ldap, radius, http
4. Services: vnc, rdp, mail, email, mx, db, ci, www, auth, proxy, pages, bastion, wiki, api, app, web, pxeboot, voip
5. Applications: postgres, mysql, mongo, jenkins, gitlab, vpn, grafana, prometheus, elastic, redis, oracle, kafka, ceph, clickhouse, couch, cassandra, influx, gerrit, memcached, samba, openstack, mattermost, zabbix, wireguard, jupyter, k8s, maria, hadoop, asterisk, shib, portal
6. Frameworks: wordpress, drupal, joomla, django, rails, glassfish, plone, apex, tomcat, websphere
7. Context: dev, test, staging, debug, private, intranet, backup, mgmt, sandbox, dmz, public, external, internal, core, sensitive, prod, preprod, perf
8. Cloud Providers: amazonaws, azure, gcp, ovh, digitalocean, linode, hetzner, aliyun, oraclecloud
9. Security Tools: siem, ids, ips, antivirus, crowdstrike, defender, sentinel, falcon, edr
10. Business Units: finance, sales, legal, marketing, corp, ops, adm, analytics
11. Operating Systems: linux, windows, debian, ubuntu, centos, rhel, vmware, esxi, xen, iis

Output a list of terms relevant for security analysis. For each term you identify, indicate which of the 11 classes it belongs to.

Strictly follow the following rules:
- Just return the output.
- Identify terms only in the list of words provided by the user.
- Output only terms highly relevant in the context of security analysis. Be selective.
- Output JSON indicating the identified term its associated class.
- Do not output terms already provided as examples above.
- Do not provide explanations, introductions, or reflections.
- Don't think again the output after you read a word, just write the output.
"""

TAR_OUTPUT = BASE_PATH / 'relevant_words.tar'

with tarfile.open(TAR_OUTPUT, mode='w') as tar:
    for index, word_block in enumerate(blocks_of_words):
        block_num = index + 1

        print(f"\nProcessing Block {block_num}...")

        prompt = f"""
        {word_block}
        """

        print(f"Sending prompt for Block {block_num}...")
        try:
            out = llm.chat.completions.create(
                model="llama-3-70b-q6",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
            )
            if out:
                finish_reason = out.choices[0].finish_reason
                if finish_reason == "length":
                    continue

                relevant_lines = out.choices[0].message.content.strip().split("\n")
                content = "\n".join(relevant_lines) + "\n"

                data = content.encode('utf-8')
                file_like = io.BytesIO(data)
                filename = f"block_{block_num}"

                tarinfo = tarfile.TarInfo(name=f'{filename}.txt')
                tarinfo.size = len(data)
                tar.addfile(tarinfo=tarinfo, fileobj=file_like)

                print(f"Block {block_num} saved to in .tar")
            else:
                print(f"TIMEOUT: {block_num}")
        except Exception as e:
            print(f"ERROR in Block {block_num}: {e}")
