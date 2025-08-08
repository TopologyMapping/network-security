# Censys

This is a command-line tool for downloading [Censys](https://censys.io)'s Universal Internet Dataset V2 (IPv4) and IPv6 scan dumps using their public API.

## Features

- Download one or multiple scan dumps by date.
- Support for resuming downloads from a specific file.
- Interactive or scripted mode.
- Retry logic and MD5 integrity checks.
- Authentication via file or command-line arguments.


## Usage

* Basic usage: `python download.py --dumps 20240801`
* Interactive mode: `python download.py --interactive`
* Download ipv6 dump: `python download.py --dataset="https://search.censys.io/api/v1/data/universal-internet-dataset-v2-ipv4" --dumps 20240801`
* Download range of dates: `python download.py --dumps 20240801-20240805`
* Download all dumps after a date: `python download.py --dumps ">20240701"`
* Download all dumps before a date: `python download.py --dumps "<20240701"`
* Download multiple specific dates: `python download.py --dumps 20240701,20240708,20240801`
* Resume a specific file (useful for long dumps): `python download.py --dumps 20240801 --resume_file ipv4-000000002000.avro`

##  Authentication

You can authenticate using either:

* Option 1: API credentials file (default)

Create a file at ~/.config/censys.apikey with the following content:

```
APIID=your_api_id
APIKEY=your_api_key
```

* Option 2: Command-line arguments

```
python download.py --dumps 20240801 --api-id="your_api_id" --api-key="your_api_key"
```
