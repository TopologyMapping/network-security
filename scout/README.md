# scout

Scout Module for Security Scanning

## Scout module configuration

```python
class ScoutConfig:
    credentials_file: pathlib.Path
    output_dir: pathlib.Path
    docker_image: str = "rossja/ncc-scoutsuite:aws-latest"
    docker_poll_interval: float = 16.0
    docker_socket: str | None = None
    docker_timeout: int = 5
```

The `credentials_file` should contain the AWS credentials and will be mounted at `/root/.aws/credentials` inside the container, so Scout can authenticate seamlessly.

> The `tests/testrun.py` script assumes that the credentials file is copied to `security-modules/scout/dev/aws-credentials`.

The `output_dir` should point to a directory where the Scout outputs will be placed.  For each submitted task (see below), we generate a new directory `output_dir/{task.label}` with the outputs.

## AWS credentials configuration

### Install the AWS CLI

* How to configure the AWS CLI without root ([StackOverflow](https://stackoverflow.com/a/67165838/7196827)):

    ```bash
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    ./aws/install -i $HOME/bin/aws-cli -b $HOME/bin/
    ```

### Setting up a user and CLI credentials

* Create AWS user and access keys ([AWS docs](https://docs.aws.amazon.com/powershell/latest/userguide/pstools-appendix-sign-up.html))
  * On a personal account, use a plain access key
  * For a larger organization, use of SSO and IAM is advised
* Run `aws configure` to set up the credentials

## Testing ScoutSuite

* Skip testing Scout on a local install because it does not support Python 3.9+

* Test using Docker running `docker compose run -ti scout`

* We could have integrated Scout using Python's `asyncio`, but then we would have problems with Python versioning as Scout only supports Python 3.6-3.8.