#!/bin/bash

# assuming shodan data is stored with filename format: BR.[year][month][day].json.bz2 like: BR.20231108.json.bz2

# inform the date to be analized (month, start and end day)
month=""
startDay=""
endDay=""

# enter the input directory with all the original shodan data and the output to save the results (data filtered at UFMG)
inputDirectoryOriginalShodanData=""
outputDirectoryDataFilterUfmg=""

# enter the input directory with all the original censys data
inputDirectoryOriginalCensysData=""

# enter the output directory to store Censys data formated
outputDirectoryCensysFormatted=""

# enter the input directory with shodan OR censys (formated) data to be analyzed and the outputh path
inputDirectoryToBeAnalyzed=""
outputPathResultAnalysis=""

# enter the outputh path to store the temporal scan results
outputPathTemporalScan=""

python3 filter_ufmg_shodan.py $month $startDay $endDay $inputDirectoryOriginalShodanData $outputDirectoryDataFilterUfmg
python3 load_censys_in_shodan_format.py $inputDirectoryOriginalCensysData $outputDirectoryCensysFormatted
python3 probe_data_shodan_and_censys.py $inputDirectoryToBeAnalyzed $outputPathResultAnalysis
python3 temporal_scan_ip_shodan.py $inputDirectoryToBeAnalyzed $outputPathTemporalScan