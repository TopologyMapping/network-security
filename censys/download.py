#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ChunkedEncodingError
from urllib3.util import Retry
from http.client import IncompleteRead
import hashlib
import time

HELP = """
* Type YYYYMMDD to download only the specified dump;
* Type YYYYMMDD,YYYYMMDD,...,YYYYMMDD to download multiple dumps;
* Type >YYYYMMDD to download all dumps greather than the specification;  
* Type <YYYYMMDD to download all dumps less than the specification;
* Type YYYYMMDD-YYYYMMDD to download all dumps between range;
"""

def create_parser():
    desc = """Download Censys scan data"""
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument(
        "--interactive",
        required=False,
        help="Run this script in interactive mode.",
        action="store_true"
    )

    parser.add_argument(
        "--dumps",
        dest="dumps",
        action="store",
        type=str,
        required=False,
        help=f"Download a specificated date:\n {HELP}"
    )

    parser.add_argument(
        "--resume_file",
        dest="resume_file",
        action="store",
        type=str,
        required=False,
        help=f"Download from a specificated filename (e.g., ipv4-000000008738.avro). Note: Only works when downloading a single date."
    )

    parser.add_argument(
        "--dataset",
        dest="dataset",
        action="store",
        metavar="DATASET",
        type=str,
        required=False,
        help="Url to download Censys's data [%(default)s]",
        default="https://search.censys.io/api/v1/data/universal-internet-dataset-v2-ipv4",
    )

    parser.add_argument(
        "--api-file",
        dest="apifp",
        action="store",
        metavar="FILE",
        type=str,
        required=False,
        help="Path to file containing APIID and APIKEY [%(default)s]",
        default="~/.config/censys.apikey",
    )

    parser.add_argument(
        "--api-id",
        dest="apiid",
        action="store",
        metavar="STR",
        type=str,
        required=False,
        help="APIID to use when making requests [--keyfile]",
    )

    parser.add_argument(
        "--api-key",
        dest="apikey",
        action="store",
        metavar="STR",
        type=str,
        required=False,
        help="APIKEY to use when making requests [--keyfile]",
    )
    return parser


def _read_apiid_apikey(path: str) -> tuple[str, str]:
    with open(os.path.expanduser(path), encoding="utf8") as fd:
        apiid_str, apiid = fd.readline().strip().split("=")
        assert apiid_str == "APIID"
        apikey_str, apikey = fd.readline().strip().split("=")
        assert apikey_str == "APIKEY"
    return apiid, apikey

def _get_permissions(opts):

    if opts.apiid and opts.apikey:
        auth = (opts.apiid, opts.apikey)
    elif opts.apifp: 
        auth = _read_apiid_apikey(opts.apifp)
    return auth

def _list_dumps(opts: argparse.Namespace) -> list[str]:

    auth = _get_permissions(opts)
    r: requests.Response = requests.get(opts.dataset, auth=auth)
    r.raise_for_status()
    data = [r['id'] for r in r.json()["results"]["historical"]]
    return data

def _download_file_list(opts: argparse.Namespace, day: str) -> dict[str, dict[str, str]]:
    auth = _get_permissions(opts)
    r: requests.Response = requests.get(f"{opts.dataset}/{day}", auth=auth)
    r.raise_for_status()
    data = r.json()['files']
    return data

def _download_file(opts, url, local_filename, md5sum, max_attempts=5):
    auth = _get_permissions(opts)

    retry_strategy = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504, 521],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    attempt = 0
    while attempt < max_attempts:
        try:
            with session.get(url, stream=True, auth=auth, timeout=60) as r:
                r.raise_for_status()
                with open(local_filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
            computed_md5_sum = _compute_md5_sum(local_filename)
            return md5sum == computed_md5_sum
        except (ChunkedEncodingError, IncompleteRead) as e:
            attempt += 1
            print(f"Warning: Erro de leitura incompleta, tentativa {attempt}/{max_attempts}: {e}")
            time.sleep(2 * attempt)  # Exponencial backoff
        except Exception as e:
            print(f"Erro inesperado: {e}")
            break
    return False


def _compute_md5_sum(local_filename):
    with open(local_filename, "rb") as f:
        file_hash = hashlib.md5()
        while chunk := f.read(8192):
            file_hash.update(chunk)
    return file_hash.hexdigest()


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    parser = create_parser()
    opts = parser.parse_args()
    available_dumps = _list_dumps(opts)
    
    max_retries = 10

    if opts.interactive:
        dumps = _list_dumps(opts)
        download_days_str = input(f"All the following dumps are available to download: {dumps}\n{HELP}\nChoose one option: ")
    elif opts.dumps:
        download_days_str = opts.dumps
    else:
        logging.error(f"Parameter 'interactive' or 'dumps' must be informed.")
        return 1
    
    download_days_str = download_days_str.strip().replace(" ", "")
    if ">" in download_days_str:
        start_day = download_days_str[1:]
        index = available_dumps.index(start_day)
        download_days = available_dumps[index:]
    elif "<" in download_days_str:
        end_day = download_days_str[1:]
        index = available_dumps.index(end_day)
        download_days = available_dumps[:index+1]
    elif "-" in download_days_str:
        start_day, end_day = download_days_str.split("-")
        index_start = available_dumps.index(start_day)
        index_end = available_dumps.index(end_day)
        download_days = available_dumps[index_start:index_end+1]
    else:
        download_days = [v for v in download_days_str.split(",") if v in available_dumps]

    logging.info(f"Downloading dumps: {download_days}")
    
    resume_file = opts.resume_file if opts.resume_file else "ipv4-000000000000.avro"
    if len(download_days) > 1:
        resumed = True
    else:
        resumed = False
        
    for dump_day in download_days:
        logging.info(f"Starting dump {dump_day}")
        files_url = _download_file_list(opts, dump_day)
        try:
            os.mkdir(dump_day)
        except:
            logging.warning(f"Folder '{dump_day}' already exists")

        count = 0
        n_files = len(files_url)
        
        for filename, values in files_url.items():
            downloaded = False
            retries = 1
            count  += 1 
            remains = round(100*count/n_files,2)
            
            if not resumed:
                if resume_file in filename:
                    resumed = True
                else:
                    logging.info(f"Skipping file {filename} of dump {dump_day} ({remains}%)")

            if resumed:
                while not downloaded and (retries < max_retries):
                    logging.info(f"Downloading file {filename} of dump {dump_day} ({remains}%) - Attempt {retries}")
                    downloaded = _download_file(opts, values['download_path'], f"{dump_day}/{filename}", values['compressed_md5_fingerprint'])
                    retries += 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

