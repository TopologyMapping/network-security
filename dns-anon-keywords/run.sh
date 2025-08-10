#!/bin/bash

show_help(){
    echo "Use: $0 -file <rdns_file> -folder <folder_to_save_word_extraction>"
    echo " -f Path to rdns file"
    echo " -o Path to destination folder"
    echo " -h Show help"
    exit 1
}

RDNS_FILE=""
OUTPUT_FOLDER=""

while getopts "f:o:h" opt; do
    case "$opt" in
        f) RDNS_FILE="$OPTARG" ;;
        o) OUTPUT_FOLDER="$OPTARG" ;;
        h) show_help ;;
        \?) show_help ;;
    esac
done

if [[ -z "$RDNS_FILE" || -z "$OUTPUT_FOLDER" ]]; then
    echo "Error"
    echo
    show_help
fi

echo "Starting script 0-word_map ..."
g++ 0-word_map.cpp -o 0-word_map

echo "rDNS file: $RDNS_FILE"
echo "Output folder: $OUTPUT_FOLDER"

./0-word_map $RDNS_FILE $OUTPUT_FOLDER

echo "0-word_map Finished!"

echo "Starting 1-dns_words.py ..."

python3 1-dns_words.py --folder $OUTPUT_FOLDER

echo "1-dns_words.py Finished!"
echo "Starting 2-knee_words.py ..."

python3 2-knee_words.py

echo "2-knee_words.py Finished!"

echo "The next script attempts to connect to an LLM to send the prompt and classify the words"
echo "Enter a valid IP address and port to continue. (port default=22)"
read -rp "IP Address: " IP
read -rp "Port: " PORT

if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
    PORT=22
fi

echo "Starting 3-llm_prompt.py ..."

python3 3-llm_prompt.py --ip $IP -p $PORT
ret=$?

if [[ $ret -ne 0 ]]; then
    echo "ERROR: Please edit the script to hook in an LLM API or check the IP / PORT sent to connection."
    exit 1
fi

echo "3-llm_prompt.py Finished!"
echo "Starting 4-classified_words.py ..."

python3 4-classified_words.py

echo "4-classified_words.py Finished!"
echo "Starting 5-final_words.py ..."

python3 5-final_words.py

echo "5-final_words.py Finished!"
echo "Final words are in the file final_words.txt inside the word_list/ folder"
