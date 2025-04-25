# Hostname Anonymization Code

This code reads a set of hostnames and anonymizes them while keeping keywords that might be useful for security analyzes.  Together with IP address anonymization, this eases sharing of network scan reports between parties without exposing vulnerable assets.  All anonymized hostnames are appended with `.gtcrivo` to indicate that anonymization has taken place.

## Anonymization Method

### TLD anonymization

This code replaces the top-level domain (TLD) and first-level domain with a numeric identifier.  For example, `microsoft.com` is replaced with `nX`.  Every occurrence of `microsoft.com` will be replaced with the same `nX`, and different domains will be replaced with a number other than `X`.

If the top-level domain is a country-code TLD, then the code replaces the ccTLD, and the next *two* subdomains with a numeric identifier.  For example, `ufjf.edu.br` will be replaced with `nX`.  Optionally, it is possible to pass the `--keep-cctld` parameter to skip the country-code in the anonymization process and keep it in the resulting anonymized hostname.

Finally, ccTLDs that are known to not operate similarly to TLDs are special-cased.  The list of ccTLDs in this category is maintained in the `data/special-cctld-list.txt` file.  This file is hand-maintained.

The list of ccTLDs is downloaded with `get-tld-json.py` and stored at `data/tlds.json` by default.

### Subdomain anonymization

Subdomain anonymization is performed by replacing the subdomain name with a numeric identifier (`nX`).  If the subdomain consists of multiple dash-separated "words", then a count of the number of words will be kept in the form of `Nw`, where `N` is the number of dash-separated words.  Finally, we will append a dash-separated list of keywords in the subdomain name that match the keywords in the `data/dns-keywords.txt` file.  Note that if the same subdomain (of a given domain) appears in multiple hostnames, they will receive the same numeric identifier `nX`, and the count of words as well as keywords will also be the same, resulting in consistent anonymization.
