#!/usr/bin/env python3

import pytest 
import pathlib
from filter import UrlFilter

@pytest.fixture
def filter_instance():
    return UrlFilter()

class TestFilterUrls:
    def test_single_url(self, filter_instance):
        """Test filtering of a single URL."""
        urls = ["http://example.com/path"]
        result = filter_instance.filter_urls(urls)
        assert result == urls  

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
            "http://a.b.example.com/page",
            "http://b.example.com/other",
            "http://a.b.example.com/page",
            "http://c.b.example.com/page" 
        ]
        result = filter_instance.filter_urls(urls)
        expected = [
            "http://a.b.example.com/page",
            "http://b.example.com/other",
            "http://c.b.example.com/page"
        ]
        assert sorted(result) == sorted(expected)

    def test_case_insensitive_urls(self, filter_instance):
        """Test filtering of URLs with different cases."""
        urls = [
            "http://Example.com/Page",
            "http://example.com/page",
            "http://EXAMPLE.COM/PAGE"
        ]
        result = filter_instance.filter_urls(urls)
        expected = [
            "http://Example.com/Page"
        ]
        assert sorted(result) == sorted(expected)

    def test_no_urls(self, filter_instance):
        """Test filtering with an empty URL list."""
        urls = []
        result = filter_instance.filter_urls(urls)
        expected = []
        assert result == expected

    def test_hyphenated_subdomains(self, filter_instance):
        """Test filtering of URLs with hyphenated subdomains."""
        urls = [
            "http://sub-domain.example.com/page",
            "http://example.com/other",
            "http://sub-domain.example.com/page",
            "http://another-sub.example.com/page" 
        ]
        result = filter_instance.filter_urls(urls)
        expected = [
            "http://sub-domain.example.com/page",
            "http://example.com/other",
            "http://another-sub.example.com/page"
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

    def test_same_levels_one_result(self, filter_instance):
        """Urls with same number of levels yield one filtered result."""
        urls = [
            "http://example.com/page1",
            "http://example.com/page2",
            "http://example.com/page3"
        ]
        result = filter_instance.filter_urls(urls)
        expected = [
            "http://example.com/page1",
        ]
        assert sorted(result) == sorted(expected)

    def test_different_levels_different_results(self, filter_instance):
        """Urls with different number of levels yield different filtered results."""
        urls = [
            "http://example.com/page1",
            "http://example.com/page2/abc",
            "http://example.com/page3/def/ghi"
        ]
        result = filter_instance.filter_urls(urls)
        expected = [
            "http://example.com/page1",
            "http://example.com/page2/abc",
            "http://example.com/page3/def/ghi"
        ]
        assert sorted(result) == sorted(expected)

    def test_hyphenated_levels(self, filter_instance):
        """Urls with hyphenated levels are filtered correctly."""
        urls = [
            "http://example.com/page-one",
            "http://example.com/page-two",
            "http://example.com/page-three"
        ]
        result = filter_instance.filter_urls(urls)
        expected = [
            "http://example.com/page-one",
        ]
        assert sorted(result) == sorted(expected)

if __name__ == "__main__":
    pytest.main()