#!/bin/bash

# assuming shodan data is stored with filename format: BR.[year][month][day].json.bz2 like: BR.20231108.json.bz2

python3 filter_ufmg_shodan.py [mont] [startDay] [endDay] [inputDirectory] [outputDirectory]
python3 load_censys_in_shodan_format.py [inputDirectory] [outputDirectory]
python3 probe_data_shodan_and_censys.py [inputDirectory] [outputPath]
python3 temporal_scan_ip_shodan.py [inputDirectory] [outputPath]