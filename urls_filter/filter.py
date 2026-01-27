#!/usr/bin/env python3

import argparse
from collections import defaultdict
import json
import logging
import pathlib 
from typing import Optional

DnsKey = tuple[str, ...]

TLDS_PATH = "./data/tlds.json"  
SPECIAL_CCTLD_PATH = "./data/special-cctlds-list.txt"  
KEEP_CCTLD = False  
IMMEDIATE_CCTLD = True  
PATH_LEVELS_TO_KEEP = 1  
SUBDOMAIN_CONTEXT_LEVELS = 1  

class UrlFilter:
    def __init__(
        self,
        tlds_path: pathlib.Path = TLDS_PATH, 
        special_cctlds_path: pathlib.Path = SPECIAL_CCTLD_PATH, 
        keep_cctld: bool = KEEP_CCTLD, 
        immediate_cctld: bool = IMMEDIATE_CCTLD,
        path_levels_to_keep: int = PATH_LEVELS_TO_KEEP,
        subdomain_context_levels: int = SUBDOMAIN_CONTEXT_LEVELS,
    ) -> None:

        self.keep_cctld = keep_cctld
        self.immediate_cctld = immediate_cctld
        self.path_levels_to_keep = path_levels_to_keep
        self.subdomain_context_levels = subdomain_context_levels
        self.domain2id: dict[DnsKey, int] = {}
        self.parent2entry2id: dict[DnsKey, dict[str, int]] = defaultdict(dict)

        with open(tlds_path, "r") as f:
            tlds_data = json.load(f)
            self.tlds = {}
            for entry in tlds_data:
                tld = entry["domain"].lstrip(".")
                self.tlds[tld] = entry.get("type", "")

        with open(special_cctlds_path, "r") as f:
            self.special_cctlds = set(line.strip() for line in f if line.strip())

    def is_cctld(self, tld: str) -> bool:
        return tld in self.tlds and self.tlds[tld] == "country-code"

    def is_special_cctld(self, tld: str) -> bool:
        return tld in self.special_cctlds
    
    def anonymize_domain(self, parts: list[str]) -> DnsKey:
        tld = parts[-1]
        domkey = tuple(parts[-2:])
        if not self.immediate_cctld:
            if self.is_cctld(tld) and not self.is_special_cctld(tld):
                domkey = tuple(parts[-3:])
        if domkey not in self.domain2id:
            self.domain2id[domkey] = len(self.domain2id) + 1
        return domkey
    
    def anonymize_subdomain(self, subdomain: str, parentkey: DnsKey) -> str:
        nextid = len(self.parent2entry2id[parentkey]) + 1
        subid = self.parent2entry2id[parentkey].setdefault(subdomain, nextid)
        wordcnt = len(subdomain.split("-"))
        wordstr = f"-{wordcnt}w" if wordcnt > 1 else ""
        return f"n{subid}{wordstr}"

    def anonymize_subdomain_words(self, subdomain: str) -> str:
        wordcnt = len(subdomain.split("-"))
        return f"{wordcnt}w" 

    def anonymize_url(self, url: str) -> Optional[str]:
        if not url: 
            return None
         
        # Extracts query string
        query_string = ""
        if '?' in url:
            url_parts = url.split('?', 1)
            url = url_parts[0]
            query_string = url_parts[1]

        # Erases protocol
        parts = []
        if "://" in url:
            parts = url.split("://", 1)[1]

        # Divides URL into domain and paths
        parts = parts.split("/")
        domain = parts[0]  
        parts.pop(0)  

        # Splits the domain into parts (subdomains + domain + TLD)
        domain_parts = domain.split(".")

        # Checks if the domain has at least 2 parts (domain.tld)
        if len(domain_parts) < 2:
            logging.warning("skipping [%s]: insufficient levels", url)
            return None
        
        ccTLD = domain_parts[-1]
        
        domkey = self.anonymize_domain(domain_parts)
        domain_id_str = f"n{self.domain2id[domkey]}"

        subdomains = domain_parts[: -len(domkey)]
        anon_subdomains = []

        parentkey = domkey
        for i, subdomain in enumerate(reversed(subdomains)):
            if i < self.subdomain_context_levels:
                anonymized = self.anonymize_subdomain(subdomain, parentkey)

                parentkey = (subdomain,) + parentkey
            else:
                anonymized = self.anonymize_subdomain_words(subdomain)
            
            anon_subdomains.append(anonymized)
        anon_subdomains.reverse()
        
        anon_sub_str = ".".join(anon_subdomains) + "." if anon_subdomains else ""

        paths = parts
        anon_paths = []

        # Keeps the first N path levels as is,
        # only counts the additional levels
        num_keep_paths = min(self.path_levels_to_keep, len(paths))
        kept_paths = paths[:num_keep_paths]
        remaining_paths = paths[num_keep_paths:]

        anon_paths.extend(kept_paths)
         
        if remaining_paths:
            wordcnt = len(remaining_paths)
            wordstr = f"{wordcnt}p"
            anon_paths.append(wordstr)
        anon_path_str = ("/" + "/".join(anon_paths)) if anon_paths else ""
 
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

        if self.keep_cctld and self.is_cctld(ccTLD) and not self.is_special_cctld(ccTLD):
            return f"{anon_sub_str}{domain_id_str}.{ccTLD}{anon_path_str}{anon_query_str}"
        else:
            return f"{anon_sub_str}{domain_id_str}{anon_path_str}{anon_query_str}"
            
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
        keep_cctld=args.keep_cctld,
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