from constants import SYSTEM_PROMPT
import os
import openai
import argparse

# Defining model
LLM = openai.OpenAI(
    base_url="http://.../v1",  # server is running at gorgona1 (cluster is composed by gorgona1, gorgona5 and gorgona6), total VRAM = 72 GB
    api_key="sk-no-key-required",
)

def init_LLM(ip_port: str):
    global LLM
    LLM = openai.OpenAI(
        base_url=f"http://{ip_port}/v1",
        api_key="sk-no-key-required",
    )


def classification_text_generation(content, prompt: str) -> str:

    user_prompt = f"""
    {content}
    {prompt}
    """

    out = LLM.chat.completions.create(
        model="llama-3-70b-q6",
        messages=[
            {"role": "system", "content": f"{SYSTEM_PROMPT}"},
            {"role": "user", "content": f"{user_prompt}"},
        ],
        max_tokens=None,
    )

    return str(out.choices[0].message.content) if out else ""


def receive_arguments():
    parser = argparse.ArgumentParser(
        description="Match CVEs between Nmap, OpenVAS, and Nuclei templates."
    )
    parser.add_argument("--nmap", required=False, help="Path to the Nmap directory.")
    parser.add_argument(
        "--openvas", required=False, help="Path to the OpenVAS directory."
    )
    parser.add_argument(
        "--nuclei", required=False, help="Path to the Nuclei templates directory."
    )
    parser.add_argument(
        "--metasploit",
        required=False,
        help="Path to the metasploit templates directory.",
    )
    parser.add_argument(
        "--initialRange", type=int, required=True, help="Initial classification range."
    )
    parser.add_argument(
        "--finalRange", type=int, required=True, help="Final classification range."
    )
    parser.add_argument("--output", required=True, help="Output JSON file.")
    parser.add_argument("--ip_port", required=True, help="LLM ip and port.")

    return parser.parse_args()


def find_key_by_value(input_dict, value):
    keys = [key for key, val in input_dict.items() if val == value]
    return keys


# Try to read file with different encodings
def read_file_with_fallback(file_path):

    if not os.path.exists(file_path):
        print(file_path)
        raise Exception("Arquivo não existe")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        with open(file_path, "r", encoding="iso-8859-1") as f:
            return f.read()
