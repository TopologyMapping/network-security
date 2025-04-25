#!/usr/bin/env python3

import pytest
import pathlib
from anonymizer import HostnameAnonymizer


@pytest.fixture
def anonymizer():
    return HostnameAnonymizer(
        tlds_path=pathlib.Path("data/tlds.json"),
        special_cctlds_path=pathlib.Path("data/special-cctlds-list.txt"),
        dns_keywords_path=pathlib.Path("data/dns-keywords.txt"),
        keep_cctld=False,
    )


class TestAnonymizeDomain:
    def test_regular_domain(self, anonymizer):
        """Test anonymization of a regular domain (example.com)."""
        parts = ["example", "com"]
        domkey = anonymizer.anonymize_domain(parts)
        # Should be a tuple of the last two parts
        assert domkey == ("example", "com")
        assert isinstance(domkey, tuple)
        # Check that domain2id contains the domain and assigned an ID
        assert domkey in anonymizer.domain2id
        assert anonymizer.domain2id[domkey] == 1  # Should be the first domain
        assert len(anonymizer.parent2entry2id) == 0

    def test_subdomain_ignored(self, anonymizer):
        """Test that subdomains are ignored in domkey calculation."""
        parts = ["sub", "example", "com"]
        domkey = anonymizer.anonymize_domain(parts)
        # Should still be a tuple of the last two parts, ignoring the subdomain
        assert domkey == ("example", "com")
        assert len(anonymizer.parent2entry2id) == 0

    def test_cctld_domain(self, anonymizer):
        """Test anonymization of a ccTLD domain (example.uk)."""
        parts = ["example", "uk"]
        # First ensure uk is a ccTLD in our test data
        assert anonymizer.is_cctld("uk")
        # UK is not in special ccTLDs
        assert not anonymizer.is_special_cctld("uk")
        domkey = anonymizer.anonymize_domain(parts)
        # Should be a tuple of just the two parts as we don't have a SLD
        assert domkey == ("example", "uk")
        assert anonymizer.domain2id[domkey] == 1
        assert len(anonymizer.parent2entry2id) == 0

    def test_cctld_domain_without_sld_mangle(self, anonymizer):
        """Anonymization of a ccTLD without SLD should mangle first subdomain (sub.example.uk)."""
        # This test will fail if we ever handle this case correctly; this behavior is a result
        # of simplifications in the code.
        parts = ["sub", "example", "uk"]
        # First ensure uk is a ccTLD in our test data
        assert anonymizer.is_cctld("uk")
        # UK is not in special ccTLDs
        assert not anonymizer.is_special_cctld("uk")
        domkey = anonymizer.anonymize_domain(parts)
        # Should be a tuple of just the two parts as we don't have a SLD
        assert domkey == ("sub", "example", "uk")
        assert anonymizer.domain2id[domkey] == 1
        assert len(anonymizer.parent2entry2id) == 0

    def test_cctld_with_sld(self, anonymizer):
        """Test ccTLD with second-level domain (example.co.uk)."""
        parts = ["example", "co", "uk"]
        # First ensure uk is a ccTLD in our test data
        assert anonymizer.is_cctld("uk")
        # UK is not in special ccTLDs
        assert not anonymizer.is_special_cctld("uk")
        domkey = anonymizer.anonymize_domain(parts)
        # Should be a tuple of all three parts for a ccTLD with SLD
        assert domkey == ("example", "co", "uk")
        assert anonymizer.domain2id[domkey] == 1
        assert len(anonymizer.parent2entry2id) == 0

    def test_special_cctld(self, anonymizer):
        """Test anonymization of a special ccTLD domain (example.io)."""
        parts = ["example", "io"]
        # First ensure io is a ccTLD in our test data
        assert anonymizer.is_cctld("io")
        # IO is in special ccTLDs
        assert anonymizer.is_special_cctld("io")
        domkey = anonymizer.anonymize_domain(parts)
        # Should be treated like a normal TLD (only last two parts)
        assert domkey == ("example", "io")

    def test_special_cctld_with_subdomain(self, anonymizer):
        """Test anonymization of a special ccTLD domain with subdomain (sub.example.io)."""
        parts = ["sub", "example", "io"]
        # First ensure io is a ccTLD in our test data
        assert anonymizer.is_cctld("io")
        # IO is in special ccTLDs
        assert anonymizer.is_special_cctld("io")
        domkey = anonymizer.anonymize_domain(parts)
        # Should be treated like a normal TLD (only last two parts)
        assert domkey == ("example", "io")

    def test_domain_id_assignment(self, anonymizer):
        """Test that domain IDs are assigned incrementally."""
        parts1 = ["example", "com"]
        parts2 = ["example", "org"]
        parts3 = ["example", "co", "uk"]

        domkey1 = anonymizer.anonymize_domain(parts1)
        domkey2 = anonymizer.anonymize_domain(parts2)
        domkey3 = anonymizer.anonymize_domain(parts3)

        assert anonymizer.domain2id[domkey1] == 1
        assert anonymizer.domain2id[domkey2] == 2
        assert anonymizer.domain2id[domkey3] == 3

    def test_same_domain_same_id(self, anonymizer):
        """Test that the same domain gets the same ID when processed again."""
        parts = ["example", "com"]

        domkey1 = anonymizer.anonymize_domain(parts)
        id1 = anonymizer.domain2id[domkey1]

        # Process the same domain again
        domkey2 = anonymizer.anonymize_domain(parts)
        id2 = anonymizer.domain2id[domkey2]

        assert domkey1 == domkey2
        assert id1 == id2

    def test_edge_case_single_part(self, anonymizer):
        """Test the edge case of a domain with only one part."""
        parts = ["localhost"]
        domkey = anonymizer.anonymize_domain(parts)
        # Should still create a tuple with the single part
        assert domkey == ("localhost",)

    def test_edge_case_empty_parts(self, anonymizer):
        """Test the edge case of an empty parts list."""
        with pytest.raises(IndexError):
            anonymizer.anonymize_domain([])


class TestAnonymizeSubdomain:
    def test_basic_subdomain(self, anonymizer):
        """Test basic subdomain anonymization."""
        parentkey = ("example", "com")
        subdomain = "test"
        result = anonymizer.anonymize_subdomain(subdomain, parentkey)
        assert result == "n1-test"
        # Check that the subdomain was added to parent2entry2id
        assert parentkey in anonymizer.parent2entry2id
        assert subdomain in anonymizer.parent2entry2id[parentkey]
        assert anonymizer.parent2entry2id[parentkey][subdomain] == 1

    def test_multiple_words_in_subdomain(self, anonymizer):
        """Test subdomain with multiple words separated by hyphens."""
        parentkey = ("example", "com")
        subdomain = "web-server"
        result = anonymizer.anonymize_subdomain(subdomain, parentkey)
        assert result == "n1-2w-server-web"  # 2 words
        assert anonymizer.parent2entry2id[parentkey][subdomain] == 1

    def test_subdomain_with_keyword(self, anonymizer):
        """Test subdomain containing a known DNS keyword."""
        parentkey = ("example", "com")
        # Using "web" which is in dns-keywords.txt
        subdomain = "webhost"
        result = anonymizer.anonymize_subdomain(subdomain, parentkey)
        assert result == "n1-web"
        assert anonymizer.parent2entry2id[parentkey][subdomain] == 1

    def test_subdomain_with_multiple_keywords(self, anonymizer):
        """Test subdomain with multiple DNS keywords."""
        parentkey = ("example", "com")
        # Using "web" and "mail" which are in dns-keywords.txt
        subdomain = "webmail"
        result = anonymizer.anonymize_subdomain(subdomain, parentkey)
        assert result == "n1-mail-web"
        assert anonymizer.parent2entry2id[parentkey][subdomain] == 1

    def test_subdomain_with_keywords_and_multiple_words(self, anonymizer):
        """Test subdomain with both multiple words and keywords."""
        parentkey = ("example", "com")
        subdomain = "web-server-app"
        result = anonymizer.anonymize_subdomain(subdomain, parentkey)
        # Should have 3 words and keywords "web" and "app"
        assert result == "n1-3w-app-server-web"
        assert anonymizer.parent2entry2id[parentkey][subdomain] == 1

    def test_multiple_subdomains_same_parent(self, anonymizer):
        """Test that different subdomains under the same parent get different IDs."""
        parentkey = ("example", "com")
        subdomain1 = "test1"
        subdomain2 = "test2"

        result1 = anonymizer.anonymize_subdomain(subdomain1, parentkey)
        result2 = anonymizer.anonymize_subdomain(subdomain2, parentkey)

        assert result1 == "n1-test"
        assert result2 == "n2-test"
        assert anonymizer.parent2entry2id[parentkey][subdomain1] == 1
        assert anonymizer.parent2entry2id[parentkey][subdomain2] == 2

    def test_same_subdomain_different_parents(self, anonymizer):
        """Test that the same subdomain under different parents gets different IDs."""
        parentkey1 = ("example", "com")
        parentkey2 = ("example", "org")
        subdomain = "test"

        result1 = anonymizer.anonymize_subdomain(subdomain, parentkey1)
        result2 = anonymizer.anonymize_subdomain(subdomain, parentkey2)

        assert result1 == "n1-test"
        assert result2 == "n1-test"  # Both start at 1 for their respective parents
        assert anonymizer.parent2entry2id[parentkey1][subdomain] == 1
        assert anonymizer.parent2entry2id[parentkey2][subdomain] == 1
        # Ensure these are separate entries in the dictionary
        assert len(anonymizer.parent2entry2id) == 2

    def test_same_subdomain_same_parent(self, anonymizer):
        """Test that the same subdomain under the same parent gets the same ID when processed again."""
        parentkey = ("example", "com")
        subdomain = "test"

        result1 = anonymizer.anonymize_subdomain(subdomain, parentkey)
        result2 = anonymizer.anonymize_subdomain(subdomain, parentkey)

        assert result1 == result2 == "n1-test"
        assert anonymizer.parent2entry2id[parentkey][subdomain] == 1
        # Ensure only one entry was created
        assert len(anonymizer.parent2entry2id[parentkey]) == 1


class TestAnonymizeHostname:
    def test_basic_hostname(self, anonymizer):
        """Test anonymization of a basic hostname with no subdomains."""
        hostname = "example.com"
        result = anonymizer.anonymize_hostname(hostname)
        assert result == "n1.gtcrivo"

    def test_hostname_with_subdomain(self, anonymizer):
        """Test anonymization of a hostname with a single subdomain."""
        hostname = "test.example.com"
        result = anonymizer.anonymize_hostname(hostname)
        assert result == "n1-test.n1.gtcrivo"
        # Check internal structures
        assert ("example", "com") in anonymizer.domain2id
        assert anonymizer.domain2id[("example", "com")] == 1
        assert ("example", "com") in anonymizer.parent2entry2id
        assert anonymizer.parent2entry2id[("example", "com")]["test"] == 1

    def test_hostname_with_multiple_subdomains(self, anonymizer):
        """Test anonymization of a hostname with multiple subdomains."""
        hostname = "dev.staging.example.com"
        result = anonymizer.anonymize_hostname(hostname)
        # First n1 is dev, second n1 is staging
        assert result == "n1-dev.n1-staging.n1.gtcrivo"
        # Check nested parent-child relationships are stored correctly
        assert ("staging", "example", "com") in anonymizer.parent2entry2id
        assert anonymizer.parent2entry2id[("staging", "example", "com")]["dev"] == 1

    def test_hostname_with_keywords_in_subdomains(self, anonymizer):
        """Test that subdomains with DNS keywords are properly labeled."""
        hostname = "web.mail.example.com"
        result = anonymizer.anonymize_hostname(hostname)
        assert "web" in result and "mail" in result
        assert result == "n1-web.n1-mail.n1.gtcrivo"

    def test_cctld_hostname_without_keep(self, anonymizer):
        """Test ccTLD hostname with keep_cctld=False."""
        hostname = "example.co.uk"
        result = anonymizer.anonymize_hostname(hostname)
        # Should not include the ccTLD in the result
        assert result == "n1.gtcrivo"
        # Domain key should include all three parts
        assert ("example", "co", "uk") in anonymizer.domain2id

    def test_cctld_hostname_with_keep(self, anonymizer):
        """Test ccTLD hostname with keep_cctld=True."""
        # Create a new anonymizer with keep_cctld=True
        keep_anonymizer = HostnameAnonymizer(
            tlds_path=pathlib.Path("data/tlds.json"),
            special_cctlds_path=pathlib.Path("data/special-cctlds-list.txt"),
            dns_keywords_path=pathlib.Path("data/dns-keywords.txt"),
            keep_cctld=True,
        )
        hostname = "example.co.uk"
        result = keep_anonymizer.anonymize_hostname(hostname)
        # Should include the ccTLD in the result
        assert result == "n1.uk.gtcrivo"
        # Domain key should include all three parts
        assert ("example", "co", "uk") in keep_anonymizer.domain2id

    def test_cctld_hostname_with_keep_and_subdomain(self, anonymizer):
        """Test ccTLD hostname with keep_cctld=True and subdomain."""
        # Create a new anonymizer with keep_cctld=True
        keep_anonymizer = HostnameAnonymizer(
            tlds_path=pathlib.Path("data/tlds.json"),
            special_cctlds_path=pathlib.Path("data/special-cctlds-list.txt"),
            dns_keywords_path=pathlib.Path("data/dns-keywords.txt"),
            keep_cctld=True,
        )
        hostname = "test.example.co.uk"
        result = keep_anonymizer.anonymize_hostname(hostname)
        # Should include the ccTLD in the result
        assert result == "n1-test.n1.uk.gtcrivo"
        # Domain key should include all three parts
        assert ("example", "co", "uk") in keep_anonymizer.domain2id

    def test_special_cctld_hostname(self, anonymizer):
        """Test hostname with a special ccTLD (treated like gTLD)."""
        hostname = "example.io"
        result = anonymizer.anonymize_hostname(hostname)
        # Should be treated as a normal domain
        assert result == "n1.gtcrivo"
        # Domain key should be just the two parts
        assert ("example", "io") in anonymizer.domain2id

    def test_invalid_hostname(self, anonymizer):
        """Test with invalid hostnames."""
        # Test with empty string
        assert anonymizer.anonymize_hostname("") is None
        # Test with hostname without dots
        assert anonymizer.anonymize_hostname("localhost") is None

    def test_case_insensitive(self, anonymizer):
        """Test that hostname anonymization is case insensitive."""
        hostname1 = "Example.Com"
        hostname2 = "example.com"
        result1 = anonymizer.anonymize_hostname(hostname1)
        result2 = anonymizer.anonymize_hostname(hostname2)
        assert result1 == result2 == "n1.gtcrivo"
        # Only one entry should be created
        assert len(anonymizer.domain2id) == 1

    def test_hyphenated_subdomains(self, anonymizer):
        """Test hostname with hyphenated subdomains."""
        hostname = "web-server.example.com"
        result = anonymizer.anonymize_hostname(hostname)
        assert result == "n1-2w-server-web.n1.gtcrivo"

    def test_complex_hostname(self, anonymizer):
        """Test a complex hostname with multiple features."""
        hostname = "dev-test.web-api.mail-server.example.co.uk"
        result = anonymizer.anonymize_hostname(hostname)
        # Should have hyphenated parts, word counts, and keywords
        assert "dev-test" in anonymizer.parent2entry2id[("web-api", "mail-server", "example", "co", "uk")]
        assert "2w" in result  # For dev-test
        assert "web" in result  # Keywords
        assert "mail" in result  # Keywords
        assert "server" in result  # Part of mail-server
        assert result.endswith(".gtcrivo")
        assert result == "n1-2w-dev-test.n1-2w-api-web.n1-2w-mail-server.n1.gtcrivo"

    def test_consistency_across_calls(self, anonymizer):
        """Test that the same hostname gets the same anonymized result across calls."""
        hostname = "www.example.com"
        result1 = anonymizer.anonymize_hostname(hostname)
        result2 = anonymizer.anonymize_hostname(hostname)
        assert result1 == result2

    def test_different_hostnames_different_results(self, anonymizer):
        """Test that different hostnames get different anonymized results."""
        hostname1 = "www.example.com"
        hostname2 = "www.example.org"
        result1 = anonymizer.anonymize_hostname(hostname1)
        result2 = anonymizer.anonymize_hostname(hostname2)
        assert result1 != result2

    def test_multiple_subdomains(self, anonymizer):
        """Test that domain IDs are assigned incrementally."""
        hostname1 = "sub1.example.com"
        hostname2 = "sub2.example.com"
        hostname3 = "sub1.example.com"
        hostname4 = "sub3.example.com"
        hostname5 = "sub1.example.org"
        hostname6 = "sub2.example.org"

        domkey1 = anonymizer.anonymize_domain(hostname1.split("."))
        domkey2 = anonymizer.anonymize_domain(hostname2.split("."))
        domkey3 = anonymizer.anonymize_domain(hostname3.split("."))
        domkey4 = anonymizer.anonymize_domain(hostname4.split("."))
        domkey5 = anonymizer.anonymize_domain(hostname5.split("."))
        domkey6 = anonymizer.anonymize_domain(hostname6.split("."))

        result1 = anonymizer.anonymize_hostname(hostname1)
        result2 = anonymizer.anonymize_hostname(hostname2)
        result3 = anonymizer.anonymize_hostname(hostname3)
        result4 = anonymizer.anonymize_hostname(hostname4)
        result5 = anonymizer.anonymize_hostname(hostname5)
        result6 = anonymizer.anonymize_hostname(hostname6)

        assert anonymizer.domain2id[domkey1] == 1
        assert anonymizer.domain2id[domkey2] == 1
        assert anonymizer.domain2id[domkey3] == 1
        assert anonymizer.domain2id[domkey4] == 1
        assert anonymizer.domain2id[domkey5] == 2
        assert anonymizer.domain2id[domkey6] == 2
        assert result1 == "n1.n1.gtcrivo"
        assert result2 == "n2.n1.gtcrivo"
        assert result3 == "n1.n1.gtcrivo"
        assert result4 == "n3.n1.gtcrivo"
        assert result5 == "n1.n2.gtcrivo"
        assert result6 == "n2.n2.gtcrivo"
        assert anonymizer.parent2entry2id[domkey1]["sub1"] == 1
        assert anonymizer.parent2entry2id[domkey1]["sub2"] == 2
        assert anonymizer.parent2entry2id[domkey1]["sub3"] == 3
        assert anonymizer.parent2entry2id[domkey5]["sub1"] == 1
        assert anonymizer.parent2entry2id[domkey6]["sub2"] == 2
