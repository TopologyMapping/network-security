# security-modules
Modules for security audits
# shodan_docker

Shodan Module for Security Scanning

## Shodan module configuration

```python
class ScoutConfig:
    credentials_file: pathlib.Path
    output_dir: pathlib.Path
    docker_image: str = "shodan-image"
    docker_poll_interval: float = 16.0
    docker_socket: str | None = None
    docker_timeout: int = 5
```

The `credentials_file` should contain the API Key and will be mounted at `/root/api_key.txt` inside the container.

The `output_dir` should point to a directory where the Scout outputs will be placed.  For each submitted task (see below), we generate a new directory `output_dir/{task.label}` with the outputs.

## Testing Shodan module

* Shodan API Key: `obtain a Shodan API on the Account Overview page`
* Test using Docker running `docker compose run -ti scout`

The `api.search()` method in the Shodan API allows to search the Shodan database for specific information or services using various search filters. It helps to find devices or services based on specific criteria, such as IP address, port, hostname, operating system, or even specific banners. This method is useful for exploring the Shodan database and finding devices or services based on a specific criteria.

The results returned by `api.search()` are limited based on the Shodan API plan and privileges. Higher-tier plans provide access to more results and additional search filters.

The code saves the search results to JSON files. After performing the search with the specified network criteria, the code stores the JSON files in the `scans` folder. Each JSON file represents the search results for a specific network or IP address.

The `enqueue` method of the `Shodan` class receives a `taskcfg` parameter, which represents the IP prefixes to be executed by Shodan.

```python
command=[
        "python",
        "./shodan_script.py",
        taskcfg.ip_address
        ]
```


