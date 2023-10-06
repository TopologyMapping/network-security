# security-modules
Modules for security audits
# shodan_docker 

Shodan Module for Security Scanning

## Module configuration

The `shodan_api_key` attribute represents the Shodan API key

```python
class ScoutConfig:
    shodan_api_key: str
    docker_image: str = "shodan-image"
    docker_poll_interval: float = 16.0
    docker_socket: str | None = None
    docker_timeout: int = 5
```

##

The `ShodanTask`class now includes an attribute called `ip_prefix`.

```python
@dataclasses.dataclass(frozen=True)
class ShodanTask:
    label: str
    ip_prefix: str
```

## 

The `enqueue` method of the `Shodan` class receives a `taskcfg` parameter, which represents the IP prefixes to be executed by the `shodan_script.py`.

```python
command=[
        "python",
        "./shodan_script.py",
        taskcfg.ip_address
        ]
```

## shodan_script.py

This script is one possible implementation for scanning a network using the Shodan API.
```plaintext
I chose this method since it provides a simple and straightforward solution.
```

##


The `api.search()` method in the Shodan API allows to search the Shodan database for specific information or services using various search filters. It helps to find devices or services based on specific criteria, such as IP address, port, hostname, operating system, or even specific banners. This method is useful for exploring the Shodan database and finding devices or services based on a specific criteria.

```python
search_results = api.search(network)
```

The results returned by `api.search()` are limited based on the Shodan API plan and privileges. Higher-tier plans provide access to more results and additional search filters.

##

The code saves the search results to JSON files. After performing the search with the specified network criteria, the code stores the JSON files in the `scans` folder. Each JSON file represents the search results for a specific network or IP address.

##

## Testing Shodan module

* Shodan API Key: `obtain a Shodan API on the Account Overview page`
* Test using Docker running `docker compose run -ti scout`
