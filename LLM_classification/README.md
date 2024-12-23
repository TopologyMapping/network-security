# Distributed classification


## distributed_classification.py
**Important**: Consult some responsible for the machines to know about the available resources and how to use the LLM model in a distributed way.

The file ```distributed_classification.py``` is a script that handles the distributed classification of vulnerability scanners tools. The classification is done using a LLM model, distributed across multiple machines to gain performance.

Inside the files ```nmap.py```, ```openvas.py```, ```nuclei.py``` and ```metasploit.py``` there are different functions to collect information about each tool. These functions are important to collect the data to specify which prompt will be used for the classification. Inside the file ```constants.py``` exists the prompts to be used for each scenario.

For example, if the nmap current file contains the category 'brute', the classification will be directed to know more information about a file that performs an attack using brute force. The same happens with the other tools.

To run the code, you need to follow:

``` python3 -m venv venv ```

``` source venv/bin/activate ```

``` pip install -r requirements.txt ```

``` python3 distributed_classification.py --<SCANNER_NAME> <PATH_TO_SCANNER_FILES>  --output <OUTPUT_NAME> --initialRange INITIAL_RANGE --finalRange FINAL_RANGE --ip_port <LLM_IP_PORT> ```

Where:

- ```<SCANNER_NAME>``` is the application to be classified. Is one (or more than one) of the following options: 'nmap', 'openvas', 'nuclei', 'metasploit'.
- ```<PATH_TO_SCANNER_FILES>``` is the path to the files of the scanner tool to be classified.
- ```<OUTPUT_NAME>``` is the name of the output file to store the classification.
- ```INITIAL_RANGE``` is the initial range of the files to be classified (the classification will be performed in 'batch', so a range is necessary).
- ```FINAL_RANGE``` is the final range of the files to be classified.
- ```<LLM_IP_PORT>``` is the ip and port of the LLM model. It must be in the format: 'ip:port' like '1.2.3.4:5678'.

An example of how to run the code is (using SCANNER_NAME as 'nmap' and 'openvas'. So both of the applications will be classified):

``` python3 distributed_classification.py --nmap ../nmapFolder --openvas ../../openvasFolder --output openvas_nmap_classification_range_0_to_100.json --initialRange 0 --finalRange 100 --ip_port 1.2.3.4:5678 ```

Another example (just classifying metasploit):

``` python3 distributed_classification.py --metasploit ../metasploitFolder --output metasploit_classification_range_5400_to_5500.json --initialRange 5400 --finalRange 5500 --ip_port 1.2.3.4:5678 ```

## verify_code_similarity.py

To check if openvas files have been correctly grouped as 'similar' and 'maybe similar', you can run the ```verify_code_similarity.py``` script. The script will use LLM to check if the files are actually similar or not.

To run the code, just type:

```python3 verify_code_similarity.py --input <INPUT_FILE> --ip_port <LLM_IP_PORT> --number_of_files_compared <NUMBER_OF_FILES>```

Where:

- ```<INPUT_FILE>``` is the JSON file with the 'similars' and 'maybe_similars' groups. If this file does not exists, check the file 'openvas.py' and the function 'compare_similarity_openvas' to see how to create this file.
- ```<LLM_IP_PORT>``` is the ip and port of the LLM model. It must be in the format: 'ip:port' like '1.2.3.4:5678'.
- ```<NUMBER_OF_FILES>``` is the number of files to be compared. If the value is X, then X unique files will be compared with the 'similars' categorie, and X unique files will be compared with the 'maybe_similars' categorie. Choose a number that is big enough to have a good insight about the classification.

An example of how to run the code is:

```python3 verify_code_similarity.py --input ./results/info_similarity_NVTS_openvas.json --ip_port 1.2.3.4:5678 --number_of_files_compared 500```

## create_problems.py

Now, to analyze the results of the LLM classification, the file ```create_problems.py``` can be used. This script will create a file with the 'problems', that is, the files that were classified similarly by the LLM. The results are stored in a file in the path: ```./results/problems.json``` which is used to realize the grouping of the files in the Defect Dojo application. Also, one intermediare file is created in the path: ```./results/grouped_scripts.json```. This file contains a grouping more easier to understand, but not used.

To run the code, just type:

```python3 create_problems.py --input <INPUT_FOLDER_WITH_CLASSIFICATION_FILES>```