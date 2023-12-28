#!/bin/bash

# assuming shodan data is stored with filename format: BR.[year][month][day].json.bz2 like: BR.20231108.json.bz2

# inform the date to be analized (month, start and end day)
month=11
startDay=1
timespanDays=11

# enter the input directory with all the original shodan data and the output to save the results (data filtered at UFMG)
inputDirectoryFilterUFMG="/home/storage/datasets/survey/downloaded/"
outputDirectoryFilterUFMG="/home/franciscoaragao/ufmg_ips/"

# enter the input directory with all the original censys data
inputDirectoryLoadCensys="/home/storage/datasets/survey/censys/original/"

# enter the output directory to store Censys data formated
outputDirectoryLoadCensys="/home/franciscoaragao/analysisDataset/data_censys_and_shodan_formated/"

# enter the input directory with shodan OR censys (formated) data to be analyzed and the outputh path
inputDirectoryProbeData="/home/franciscoaragao/ufmg_ips/"
outputPathProbeData="/home/franciscoaragao/analysisDataset/results"

# enter the input directory with shodan or censys (formated) data to be analyzed throughout the days
inputDirectoryTemporalScan="/home/franciscoaragao/ufmg_ips/"

# enter the outputh path to store the temporal scan results
outputPathTemporalScan="/home/franciscoaragao/analysisDataset/results/module_and_ports.json"

python3 analysis_shodan_censys_data.py --month $month --startDay $startDay --timespanDays $timespanDays --inputDirectoryFilterUFMG $inputDirectoryFilterUFMG --outputDirectoryFilterUFMG $outputDirectoryFilterUFMG --inputDirectoryLoadCensys $inputDirectoryLoadCensys --outputDirectoryLoadCensys $outputDirectoryLoadCensys --inputDirectoryProbeData $inputDirectoryProbeData --outputPathProbeData $outputPathProbeData --inputDirectoryTemporalScan $inputDirectoryTemporalScan --outputPathTemporalScan $outputPathTemporalScan