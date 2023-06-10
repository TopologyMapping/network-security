# security-modules
Modules for security audits
# scout

Scout Module for Security Scanning

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

The `credentials_file` should contain the AWS credentials and will be mounted at `/root/.aws/credentials` inside the container, so Scout can authenticate seamlessly.

> The `tests/testrun.py` script assumes that the credentials file is copied to `security-modules/scout/dev/aws-credentials`.

The `output_dir` should point to a directory where the Scout outputs will be placed.  For each submitted task (see below), we generate a new directory `output_dir/{task.label}` with the outputs.

## Testing Shodan module

* Shodan API Key: `obtain a Shodan API on the Account Overview page`
* Test using Docker running `docker compose run -ti scout`
