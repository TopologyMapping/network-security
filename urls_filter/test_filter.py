#!/usr/bin/env python3

import pytest 
from filter import UrlFilter

@pytest.fixture
def filter_instance():
    return UrlFilter()

@pytest.fixture
def filter_instance_keep_cctld():
    return UrlFilter(keep_cctld=True)

@pytest.fixture
def filter_instance_immediate_cctld():
    return UrlFilter(immediate_cctld=True)

class TestFilterUrls:
    def test_single_url(self, filter_instance):
        """Test filtering of a single URL."""
        urls = ["http://example.com/path"]
        result = filter_instance.filter_urls(urls)
        assert result == urls  
    
    def test_single_url_identity_key(self, filter_instance):
        """Testing a single URL identity key."""
        url = "http://example.com/unique"
        result = filter_instance.anonymize_url(url)
        expected = "n1/unique"
        assert result == expected

    def test_multiple_urls(self, filter_instance):
        """Test filtering of multiple URLs with duplicates."""
        urls = [
            "http://example.com/path1",
            "http://example.com/path2",
            "http://test.com/home",
            "http://example.com/path1"  
        ]
        result = filter_instance.filter_urls(urls)
        expected = [
            "http://example.com/path1",
            "http://example.com/path2",
            "http://test.com/home"
        ]
        assert sorted(result) == sorted(expected)

    def test_urls_with_subdomain(self, filter_instance):
        """Test filtering of URLs with subdomains."""
        urls = [
            "http://sub.example.com/page",
            "http://example.com/other",
            "http://sub.example.com/page",
            "http://another.example.com/page" 
        ]
        result = filter_instance.filter_urls(urls)
        expected = [
            "http://sub.example.com/page",
            "http://example.com/other",
            "http://another.example.com/page"
        ]
        assert sorted(result) == sorted(expected)

    def test_urls_with_multiple_subdomains(self, filter_instance):
        """Test filtering of URLs with multiple subdomains."""
        urls = [
            "http://a.b.example.com/page", # 1w.n1.n1/page
            "http://b.example.com/other", # n1/other
            "http://a.b.example.com/page", # 1w.n1.n1/page
            "http://c.b.example.com/page" # 1w.n1.n1/page
        ]
        result = filter_instance.filter_urls(urls)
        expected = [
            "http://a.b.example.com/page",
            "http://b.example.com/other",
        ]
        assert sorted(result) == sorted(expected)

    def test_urls_with_multiple_subdomains_identity_key(self, filter_instance):
        """Test the identity key of URLs with multiple subdomains."""
        urls = [
            "http://a.b.example.com/page",
            "http://a.c.example.com/page",
            "http://a.b.example.com/page",
            "http://a.d.example.com/page" 
        ]
        result = [filter_instance.anonymize_url(url) for url in urls]
        expected = [
            "1w.n1.n1/page",
            "1w.n2.n1/page",
            "1w.n1.n1/page", 
            "1w.n3.n1/page" 
        ]
        assert sorted(result) == sorted(expected)

    def test_hyphenated_subdomains(self, filter_instance):
        """Test filtering of URLs with hyphenated subdomains."""
        urls = [
            "http://sub-domain.example.com/page",
            "http://sub-domain.example.com/page",
            "http://another-sub.example.com/page" 
        ]
        result = filter_instance.filter_urls(urls)
        expected = [
            "http://sub-domain.example.com/page", 
            "http://another-sub.example.com/page",
        ]
        assert sorted(result) == sorted(expected)

    def test_hyphenated_subdomains_after_context_levels(self, filter_instance):
        """Test filtering of URLs with hyphenated subdomains after context levels."""
        urls = [
            "http://a.a.example.com/page", # 1w.n1.n1/page
            "http://sub-domain.a.example.com/page", # 2w.n1.n1/page
            "http://another-sub.a.example.com/page", # 2w.n1.n1/page
            "http://sub-domain.b.example.com/page" # 2w.n2.n1/page
        ]
        result = filter_instance.filter_urls(urls)
        expected = [
            "http://a.a.example.com/page",
            "http://sub-domain.a.example.com/page",
            "http://sub-domain.b.example.com/page"
        ]
        assert sorted(result) == sorted(expected)

    def test_consistency_across_calls(self, filter_instance):
        """Test that multiple calls to filter_urls yield consistent results."""
        urls = [
            "http://example.com/path1",
            "http://example.com/path2",
            "http://test.com/home"
        ]
        result1 = filter_instance.filter_urls(urls)
        result2 = filter_instance.filter_urls(urls)
        assert sorted(result1) == sorted(result2)

    def test_different_domains_different_results(self, filter_instance):
        """Test that different domains yield different anonymized results."""
        urls = [
            "http://example1.com/page",
            "http://example2.com/page",
            "http://example3.com/page"
        ]
        result = filter_instance.filter_urls(urls)
        expected = [
            "http://example1.com/page",
            "http://example2.com/page",
            "http://example3.com/page"
        ]
        assert sorted(result) == sorted(expected)

    def test_different_levels_different_identity_keys(self, filter_instance):
        """Urls with different number of path levels yield different identity keys."""
        urls = [
            "http://example.com/page1",
            "http://example.com/page1/abc",
            "http://example.com/page1/abc/def",
            "http://example.com/page1/abc/ghi"
        ]
        result = [filter_instance.anonymize_url(url) for url in urls] 
        expected = [
            "n1/page1",
            "n1/page1/1p",
            "n1/page1/2p",
            "n1/page1/2p"
        ]
        assert sorted(result) == sorted(expected)

    def test_url_with_single_query_param_identity_key(self, filter_instance):
        """Test URL with a single query parameter."""
        url = "http://example.com/page?id=123"
        result = filter_instance.anonymize_url(url)
        expected = "n1/page?id"
        assert result == expected

    def test_url_with_multiple_query_params_identity_key(self, filter_instance):
        """Test URL with multiple query parameters."""
        url = "http://example.com/page?p=X&q=Y"
        result = filter_instance.anonymize_url(url)
        expected = "n1/page?p&q"
        assert result == expected

    def test_url_with_multiple_query_params_different_order(self, filter_instance):
        """Test that query parameter order does not matter for anonymization."""
        url1 = "http://example.com/page?p=X&q=Y"
        url2 = "http://example.com/page?q=Y&p=X"
        result1 = filter_instance.anonymize_url(url1)
        result2 = filter_instance.anonymize_url(url2) 
        assert result1 == result2

    def test_urls_with_different_query_params(self, filter_instance):
        """Test filtering URLs with different query parameter values but same names.
        Parameter values should be ignored, so these must be treated as duplicates."""
        urls = [
            "http://example.com/page?p=X&q=Y",
            "http://example.com/page?p=A&q=B",
            "http://example.com/page?p=1&q=2"
        ]
        result = filter_instance.filter_urls(urls) 
        assert len(result) == 1

    def test_urls_with_different_query_params(self, filter_instance):
        """Test filtering URLs with different query parameters.
        Different parameter names must result in different identity keys."""
        urls = [
            "http://example.com/page?p=X",
            "http://example.com/page?q=Y",
            "http://example.com/page?p=X",
            "http://example.com/page?r=Z",
            "http://example.com/page?q=Z"
        ]
        result = filter_instance.filter_urls(urls) 
        assert len(result) == 3

    def test_url_with_empty_query_param_value(self, filter_instance):
        """Test URL with query parameter that has no value."""
        url = "http://example.com/page?flag&other=value"
        result = filter_instance.anonymize_url(url)
        expected = "n1/page?flag&other"
        assert result == expected

    def test_url_with_query_and_path(self, filter_instance):
        """Test URL with both path and query parameters."""
        url = "http://example.com/api/search?query=test&limit=10"
        result = filter_instance.anonymize_url(url) 
        expected = "n1/api/1p?limit&query"
        assert result == expected
    
    def test_url_with_query_without_path(self, filter_instance):
        """Test URL with query parameters but no path."""
        url = "http://example.com?search=test&sort=date"
        result = filter_instance.anonymize_url(url)
        expected = "n1?search&sort"
        assert result == expected

    def test_url_with_three_path_levels(self, filter_instance):
        """Test that path levels beyond 1 are counted with path suffix."""
        url = "http://example.com/api/search/results"
        result = filter_instance.anonymize_url(url)
        expected = "n1/api/2p"
        assert result == expected

    def test_url_with_many_path_levels_deduplication(self, filter_instance):
        """Test that URLs with same N (N = 1) first levels are filtered by the amount of adicional levels."""
        urls = [
            "http://example.com/api/search1",
            "http://example.com/api/search2",
            "http://example.com/api/search3/extra1",
            "http://example.com/api/search4/extra2/extra3"
        ]
        result = filter_instance.filter_urls(urls) 
        assert len(result) == 3

    def test_regular_cctld(self, filter_instance):
        """Test URL with regular ccTLD (not special) identity key."""
        url = "http://example.uk/page"
        result = filter_instance.anonymize_url(url)
        # Regular ccTLDs use 3-level domain key (domain + cc tld)
        expected = "n1/page"
        assert result == expected

    def test_regular_cctld_with_keep_flag(self, filter_instance_keep_cctld):
        """Test URL with regular ccTLD and keep_cctld flag identity key."""
        url = "http://example.uk/page"
        result = filter_instance_keep_cctld.anonymize_url(url) 
        expected = "n1.uk/page"
        assert result == expected

    def test_special_cctld(self, filter_instance):
        """Test URL with special ccTLD identity key."""
        url = "http://example.co/page"
        result = filter_instance.anonymize_url(url)
        expected = "n1/page"
        assert result == expected

    def test_special_cctld_with_keep_flag(self, filter_instance_keep_cctld):
        """Test URL with special ccTLD and keep_cctld flag."""
        url = "http://example.co/page"
        result = filter_instance_keep_cctld.anonymize_url(url)
        # Special CC TLDs don't get kept even with keep_cctld=True
        expected = "n1/page"
        assert result == expected
    
    def test_no_urls(self, filter_instance):
        """Test filtering with an empty URL list."""
        urls = []
        result = filter_instance.filter_urls(urls)
        expected = []
        assert result == expected

if __name__ == "__main__":
    pytest.main()