#!/usr/bin/env python3

import json
import logging
import sys

PREFIX_TO_ANNOUNCE = "184.164.224.0/24"
route_count = 0
announced = False
log = logging.getLogger(__name__)


def announce_route() -> None:
    log.info(f"Announcing route {PREFIX_TO_ANNOUNCE}")
    print(f"announce route {PREFIX_TO_ANNOUNCE} next-hop self", flush=True)
    print("announce eor", flush=True)


def handle_message(msg: dict) -> None:
    global route_count, announced

    msg_type = msg.get("type")
    log.debug(f"Full message: {json.dumps(msg)}")

    if msg_type == "state":
        state = msg.get("neighbor", {}).get("state")
        if state in ("established", "up") and not announced:
            logging.info("Session established")
            announce_route()
            announced = True
        elif state not in ("established", "up"):
            announced = False
            route_count = 0

    elif msg_type == "update":
        neighbor = msg.get("neighbor", {})
        message = neighbor.get("message", {})

        if "eor" in message:
            log.info(f"End-of-RIB received. Total routes: {route_count}")
            return

        if update := message.get("update"):
            announced_routes = update.get("announce", {}).get("ipv4 unicast", {})
            for _nexthop, nlri_list in announced_routes.items():
                for nlri in nlri_list:
                    if (prefix := nlri.get("nlri")) is not None:
                        log.debug(f"Received route for {prefix}")
                        route_count += 1

def main() -> None:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    log.debug("Starting ExaBGP route announcer")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            log.info("ExaBGP terminated")
            break
        try:
            if line == "done":
                log.debug("Command accepted by ExaBGP")
                continue
            msg = json.loads(line)
            handle_message(msg)
        except json.JSONDecodeError as e:
            log.error(f"Invalid JSON: {e}")
        except Exception as e:
            log.error(f"General Excepetion: {e}")


if __name__ == "__main__":
    main()
