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


blocks_of_words = split_into_blocks(INPUT_FILE, 250)

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

with open('prompt.txt', 'r') as f:
    SYSTEM_PROMPT = f.read()


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
