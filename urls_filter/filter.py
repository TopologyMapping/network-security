#!/usr/bin/env python3

import argparse
import json
import logging
import pathlib 
from typing import Optional

TLDS_PATH = "./data/tlds.json"  
SPECIAL_CCTLD_PATH = "./data/special-cctlds-list.txt"  
IMMEDIATE_CCTLD = True  
PATH_LEVELS_TO_KEEP = 1 # Number of path levels to keep in the anonymized URL (e.g., 1 keeps the first level, 2 keeps the first two levels, etc.) 
SUBDOMAIN_CONTEXT_LEVELS = 1 # Number of subdomain levels to keep as context before anonymizing the rest (e.g., 1 keeps the immediate subdomain, 2 keeps the immediate and next subdomain, etc.)

class UrlFilter:
    def __init__(
        self,
        tlds_path: pathlib.Path = pathlib.Path(TLDS_PATH), 
        special_cctlds_path: pathlib.Path = pathlib.Path(SPECIAL_CCTLD_PATH), 
        path_levels_to_keep: int = PATH_LEVELS_TO_KEEP,
        subdomain_context_levels: int = SUBDOMAIN_CONTEXT_LEVELS,
        immediate_cctld: bool = IMMEDIATE_CCTLD,
    ) -> None:

        self.immediate_cctld = immediate_cctld
        self.path_levels_to_keep = path_levels_to_keep
        self.subdomain_context_levels = subdomain_context_levels

        try:
            with open(tlds_path, "r") as f:
                tlds_data = json.load(f)
                self.tlds = {entry["domain"].lstrip("."): entry.get("type", "") for entry in tlds_data}
        except FileNotFoundError:
            logging.error(f"TLDs file not found: {tlds_path}")
            exit(1)

        try:
            with open(special_cctlds_path, "r") as f:
                self.special_cctlds = set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            logging.warning(f"Special ccTLDs file not found: {special_cctlds_path}. Proceeding without special ccTLDs.")
            self.special_cctlds = set()

    def is_tld(self, tld: str) -> bool:
        return tld in self.tlds

    def is_cctld(self, tld: str) -> bool:
        return tld in self.tlds and self.tlds[tld] == "country-code"

    def is_special_cctld(self, tld: str) -> bool:
        return tld in self.special_cctlds

    def get_domkey_parts(self, parts: list[str]) -> list[str]:
        tlds = list() 
        for part in reversed(parts):
            if self.is_tld(part):
                tlds.append(part)
            else:
                break
        
        domkey_parts = parts[-(len(tlds) + 1):]
        return domkey_parts
    
    def get_word_count_str(self, subdomain: str) -> str:
        wordcnt = len(subdomain.split("-"))
        return f"{wordcnt}w" 

    def anonymize_paths(self, paths: list[str]) -> list[str]:
        anon_paths = []
        num_keep_paths = min(self.path_levels_to_keep, len(paths))

        # Keeps the first N path levels as they are
        anon_paths.extend(paths[:num_keep_paths])

        # Turn the rest into word counts
        for path in paths[num_keep_paths:]:
            anon_paths.append(self.get_word_count_str(path))

        return anon_paths

    def anonymize_url(self, url: str) -> Optional[str]:
        if not url: return None
         
        # Extracts query string
        query_string = ""
        if '?' in url:
            url, query_string = url.split('?', 1)

        # Extracts protocol and host 
        if "://" not in url: return None
        protocol, rest = url.split("://", 1)
        if protocol not in ("http", "https"):
            logging.warning("skipping [%s]: unsupported protocol", url)
            return None
        url_parts = rest.split("/", 1) 
        domain_str, path_str = url_parts[0], (url_parts[1] if len(url_parts) > 1 else "")

        # Splits the domain into parts (subdomains + domain + TLDs)
        domain_parts = domain_str.split(".")
        
        # Checks if the domain has at least 2 parts (domain.tld)
        if len(domain_parts) < 2:
            logging.warning("skipping [%s]: insufficient levels in host", url)
            return None
        
        domkey_parts = self.get_domkey_parts(domain_parts)
        base_domain_str = ".".join(domkey_parts)

        subdomains = domain_parts[: -len(domkey_parts)]
        anon_subdomains = []
        for i, subdomain in enumerate(reversed(subdomains)):
            if i < self.subdomain_context_levels:
                anon_subdomains.append(subdomain)
            else:
                anon_subdomains.append(self.get_word_count_str(subdomain))
        anon_subdomains.reverse()
        anon_subdomain_str = ".".join(anon_subdomains) + "." if anon_subdomains else ""

        # Process paths
        anon_paths = self.anonymize_paths(path_str.split("/")) 
        anon_path_str = ("/" + "/".join(anon_paths)) if anon_paths != [''] else ""

        # Normalizes query string by keeping only parameter names and sorting them
        anon_query_str = ""
        if query_string:
            param_names = []
            for param in query_string.split('&'):
                if '=' in param:
                    param_name = param.split('=', 1)[0]
                else:
                    param_name = param
                if param_name:
                    param_names.append(param_name)
            
            # Sorts parameter names for consistency
            if param_names:
                param_names = sorted(param_names) 
                anon_query_str = "?" + "&".join(param_names)

        identity_key = f"{protocol}://{anon_subdomain_str}{base_domain_str}{anon_path_str}{anon_query_str}"
        return identity_key 

    def filter_urls(self, urls: list) -> list:
        anonymized_urls = dict()
        for url in urls:
            anonymized = self.anonymize_url(url)
            if anonymized != None and anonymized not in anonymized_urls:
                anonymized_urls[anonymized] = url
        return list(anonymized_urls.values())
            
def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Filter URL's")
    parser.add_argument(
        "--keep-cctld",
        action="store_true",
        default=False,
        help="Keep country-code TLDs in anonymized hostnames [%(default)s]",
    )
    parser.add_argument(
        "--immediate-cctld",
        action="store_true",
        default=False,
        help="Assume domain names do not have generic TLDs like .com or .org [%(default)s]",
    )
    parser.add_argument(
        "--path-levels",
        type=int,
        default=PATH_LEVELS_TO_KEEP,
        help="Number of path levels to preserve in URL anonymization [%(default)s]",
    )
    parser.add_argument(
        "--subdomain-context-levels",
        type=int,
        default=SUBDOMAIN_CONTEXT_LEVELS,
        help="Number of subdomain context levels to anonymize with IDs [%(default)s]",
    )
    parser.add_argument(
        "--tlds-file",
        metavar="JSON",
        type=pathlib.Path,
        default="data/tlds.json",
        help="Path to the TLDs JSON file [%(default)s]",
    )
    parser.add_argument(
        "--special-cctlds-file",
        metavar="FILE",
        type=pathlib.Path,
        default="data/special-cctlds-list.txt",
        help="Path to the special ccTLDs list file [%(default)s]",
    ) 
    parser.add_argument(
        "--urls-file",
        metavar="FILE",
        type=pathlib.Path,
        help="Read URL's from file (one per line)",
        required=True,
    )
    parser.add_argument(
        "--output-file",
        metavar="FILE",
        type=pathlib.Path,
        help="Write filtered URL's (one per line)",
        required=True,
    )
    return parser    

def main() -> None:
    parser = create_parser()
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)

    with open(args.urls_file, "r") as fd:
        urls = [line.strip() for line in fd if line.strip()]

    filter = UrlFilter(
        tlds_path=args.tlds_file,
        special_cctlds_path=args.special_cctlds_file, 
        immediate_cctld=args.immediate_cctld,
        path_levels_to_keep=args.path_levels,
        subdomain_context_levels=args.subdomain_context_levels,
    )

    filtered_urls = filter.filter_urls(urls) 

    with open(args.output_file, "w") as f:
        for url in filtered_urls:
            f.write(url + '\n')

if __name__ == "__main__":
    main()