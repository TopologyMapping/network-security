#!/usr/bin/env python3

import argparse
from collections import defaultdict
import json
import logging
import pathlib
from typing import Optional

GTCRIVO_SUFFIX = "gtcrivo"

DnsKey = tuple[str, ...]


class HostnameAnonymizer:
    def __init__(
        self,
        tlds_path: pathlib.Path,
        special_cctlds_path: pathlib.Path,
        dns_keywords_path: pathlib.Path,
        keep_cctld: bool,
    ) -> None:
        self.keep_cctld = keep_cctld
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

    def anonymize_hostname(self, hostname: str) -> Optional[str]:
        if not hostname:
            return None
        hostname = hostname.lower()
        parts = hostname.split(".")

        if len(parts) < 2:
            logging.warning("skipping [%s]: insufficient levels", hostname)
            return None

        domkey = self.anonymize_domain(parts)
        domain_id_str = f"n{self.domain2id[domkey]}"

        subdomains = parts[: -len(domkey)]
        anon_subdomains = []

        parentkey = domkey
        for subdomain in reversed(subdomains):
            anonymized = self.anonymize_subdomain(subdomain, parentkey)
            anon_subdomains.append(anonymized)
            parentkey = (subdomain,) + parentkey
        anon_subdomains.reverse()

        anon_sub_str = ".".join(anon_subdomains) + "." if anon_subdomains else ""
        if self.keep_cctld and self.is_cctld(parts[-1]) and not self.is_special_cctld(parts[-1]):
            return f"{anon_sub_str}{domain_id_str}.{parts[-1]}.{GTCRIVO_SUFFIX}"
        else:
            return f"{anon_sub_str}{domain_id_str}.{GTCRIVO_SUFFIX}"


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Anonymize hostnames")
    parser.add_argument(
        "--keep-cctld",
        action="store_true",
        default=False,
        help="Keep country-code TLDs in anonymized hostnames [%(default)s]",
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
        "--hosts-file",
        metavar="FILE",
        type=pathlib.Path,
        help="Read hostnames from file (one per line)",
        required=True,
    )
    return parser


def main() -> None:
    parser = create_parser()
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)

    with open(args.hosts_file, "r") as fd:
        hostnames = [line.strip() for line in fd if line.strip()]

    anonymizer = HostnameAnonymizer(
        tlds_path=args.tlds_file,
        special_cctlds_path=args.special_cctlds_file,
        dns_keywords_path=args.dns_keywords_file,
        keep_cctld=args.keep_cctld,
    )

    for hostname in hostnames:
        anonymized = anonymizer.anonymize_hostname(hostname)
        logging.info(f"{hostname} -> {anonymized}")


if __name__ == "__main__":
    main()
