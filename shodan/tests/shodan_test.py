#!/usr/bin/env python3

import logging
import os
import pathlib
import sys
import time

import shodan  # Import the Shodan module you created


CWD = pathlib.Path(os.getcwd())
assert pathlib.Path(CWD / __file__).exists(), "Run from inside tests/ with ./testrun.py"
SHODAN_MOD_PATH = CWD.parent


def callback(label: str, success: bool) -> None:
    logging.info("Callback for %s running, success=%s", label, success)


def main():
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting Shodan module")
    cfg = shodan.ShodanConfig(
        pathlib.Path(SHODAN_MOD_PATH / "dev/shodan-credentials"),
        pathlib.Path(SHODAN_MOD_PATH / "data"),
        docker_image="shodan-image",
        docker_poll_interval=1.0,
    )
    logging.info("Shodan module started")
    s = shodan.Shodan(cfg, callback)
    logging.info("Submitting task to Shodan module")
    taskcfg = shodan.ShodanTask(
        time.strftime("shodan-%Y%m%d-%H%M%S"),
        "ip_address"
    )
    s.enqueue(taskcfg)
    logging.info("Task submitted")
    s.shutdown()


if __name__ == "__main__":
    sys.exit(main())
