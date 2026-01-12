#!/usr/bin/env python3

import argparse
from collections import defaultdict
import json
import logging
import pathlib 
from typing import Optional

GTCRIVO_SUFFIX = "gtcrivo"

DnsKey = tuple[str, ...]

TLDS_PATH = "./data/tlds.json"
SPECIAL_CCTLD_PATH = "./data/special-cctlds-list.txt"
DNS_KEYWORDS_PATH = "./data/dns-keywords.txt"
KEEP_CCTLD = False
IMMEDIATE_CCTLD = True

class UrlFilter:
    def __init__(
        self,
        tlds_path: pathlib.Path = TLDS_PATH, 
        special_cctlds_path: pathlib.Path = SPECIAL_CCTLD_PATH,
        dns_keywords_path: pathlib.Path = DNS_KEYWORDS_PATH,
        keep_cctld: bool = KEEP_CCTLD, 
        immediate_cctld: bool = IMMEDIATE_CCTLD,
    ) -> None:

        self.keep_cctld = keep_cctld
        self.immediate_cctld = immediate_cctld
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

        with open(dns_keywords_path, "r") as f:
            self.dns_keywords = list(line.strip() for line in f if line.strip())

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
        keywords = [kw for kw in self.dns_keywords if kw in subdomain]
        kwstr = "-" + "-".join(keywords) if keywords else ""
        return f"n{subid}{wordstr}{kwstr}"
    
    def anonymize_path(self, subdomain: str, parentkey: DnsKey) -> str:
        nextid = len(self.parent2entry2id[parentkey]) + 1
        subid = self.parent2entry2id[parentkey].setdefault(subdomain, nextid)
        wordcnt = len(subdomain.split("/"))
        wordstr = f"-{wordcnt}w" if wordcnt > 1 else ""

        return wordstr 
    
    def anonymize_url(self, url: str) -> Optional[str]:
        if not url: 
            return None
        
        url = url.lower()
        url = url.split('?')[0]

        parts = []
        if "://" in url:
            parts = url.split("://", 1)[1]

        parts = parts.split("/", 1)
        domain = parts[0]
        parts.pop(0)

        domain_parts = domain.split(".")
        if len(domain_parts) < 2:
            logging.warning("skipping [%s]: insufficient levels", url)
            return None
        domkey = self.anonymize_domain(domain_parts)
        domain_id_str = f"n{self.domain2id[domkey]}"

        subdomains = domain_parts[: -len(domkey)]
        anon_subdomains = []

        parentkey = domkey
        for subdomain in reversed(subdomains):
            anonymized = self.anonymize_subdomain(subdomain, parentkey)
            anon_subdomains.append(anonymized)
            parentkey = (subdomain,) + parentkey
        anon_subdomains.reverse()

        anon_sub_str = ".".join(anon_subdomains) + "." if anon_subdomains else ""

        paths = parts
        anon_paths = []

        parentkey = domkey
        for path in reversed(paths):
            anonymized = self.anonymize_path(path, parentkey)
            anon_paths.append(anonymized)
            parentkey = (path,) + parentkey
        anon_paths.reverse()

        anon_path_str = "/".join(anon_paths) if anon_paths else ""

        if self.keep_cctld and self.is_cctld(parts[-1]) and not self.is_special_cctld(parts[-1]):
            if len(anon_path_str) > 0:
                return f"{anon_sub_str}{domain_id_str}.{parts[-1]}.{anon_path_str}.{GTCRIVO_SUFFIX}"
            else:
                return f"{anon_sub_str}{domain_id_str}.{parts[-1]}.{GTCRIVO_SUFFIX}" 
        else:   
            if len(anon_path_str) > 0:
                return f"{anon_sub_str}{domain_id_str}.{anon_path_str}.{GTCRIVO_SUFFIX}"
            else:
                return f"{anon_sub_str}{domain_id_str}.{GTCRIVO_SUFFIX}"
            
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
        "--dns-keywords-file",
        metavar="FILE",
        type=pathlib.Path,
        default="data/dns-keywords.txt",
        help="Path to the DNS keywords list file [%(default)s]",
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
        dns_keywords_path=args.dns_keywords_file,
        keep_cctld=args.keep_cctld,
        immediate_cctld=args.immediate_cctld,
    )

    filtered_urls = filter.filter_urls(urls) 

    with open(args.output_file, "w") as f:
        for url in filtered_urls:
            f.write(url + '\n')


if __name__ == "__main__":
    main()