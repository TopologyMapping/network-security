# ExaBGP Route Announcer

A simple ExaBGP program that establishes a BGP session, announces a prefix, and counts received routes.

## Features

- Establishes BGP session with a peer
- Announces the prefix 184.164.224.0/24
- Counts routes received during initial table transfer
- Prints total route count when End-of-RIB is received

## Installation

```bash
uv sync
```

## Usage

```bash
(cd bird && sudo ./run-bird.sh)
uv run exabgp exabgp.conf
```
