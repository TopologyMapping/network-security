# GT-Crivo — Extraction of Relevant Words from rDNS

This module of GT-Crivo implements a complete pipeline for processing Reverse DNS (rDNS) records, extracting potentially relevant tokens, and producing a refined list that can be used as a feature in the vulnerability prioritization model.

The scripts can be run individually for manual/step-by-step control, or all together through `run.sh` for full automation.

A host’s rDNS often contains hints about:
- Service or role: `mail`, `vpn`, `db`, `proxy`
- Technical function: `backup`, `api`, `test`, `auth`

In this context, we explicitly avoid tokens that represent geographic locations or company/brand names, as these do not directly indicate vulnerability risk. The focus is solely on services, technical components, and functional descriptors that can correlate with the criticality of vulnerabilities.

The hypothesis is that specific words (tokens) in rDNS strings may indicate a higher operational importance or exposure surface, which can help prioritize remediation.

The pipeline is designed to:
1. Parse rDNS into tokens
2. Filter noise and irrelevant patterns
3. Select candidates based on statistical frequency
4. Use an LLM to semantically classify them
5. Apply custom include/exclude lists for final refinement

## Structure

- 0-word_map.cpp # Extract tokens from rDNS and count frequencies per level
- 1-dns_words.py # Merge tokens from all levels, remove numeric-only entries
- 2-knee_words.py # Use KneeLocator to determine frequency cutoff
- 3-llm_prompt.py # Send candidate tokens to LLM for classification
- 4-classified_words.py # Filter and consolidate LLM-classified words
- 5-final_words.py # Apply include/exclude rules, generate final word list

## Usage

You can run each script separately if you want full control over intermediate outputs, or run `run.sh` to perform all steps in sequence.

### Automated run

chmod +x run.sh
./run.sh -f `<rdns_file.json>` -o `<output_folder>`

### Parameters

- `-f` — Path to the JSON file containing PTR records (rDNS data).
  Example: `data/rdns_results.json`

- `-o` — Output folder for all intermediate and final files.
  Example: `output/`

## Detailed Pipeline

1. `0-word_map.cpp`
   - Reads the rDNS JSON file provided via the `-f` parameter.
   - Splits each domain into hierarchical levels separated by `.`.
   - Further splits each level by `-` and `,` to isolate tokens.
   - Generates separate files:
     - `wordlist_level_0.txt`
     - `wordlist_level_1.txt`
     - ... (one per DNS level)
   - Each file contains token → frequency pairs.

2. `1-dns_words.py`
   - Combines all level-based word lists into a single dataset.
   - Removes tokens that are purely numeric.
   - Saves the result in `wordlist_wonumber.pkl`, sorted by frequency (descending).

3. `2-knee_words.py`
   - Loads `wordlist_wonumber.pkl`.
   - Uses KneeLocator to find the "elbow" point in the frequency distribution curve.
   - Tokens above this threshold are considered candidate words.
   - Outputs `wordlist_to_llm.txt` with the candidate tokens.

4. `3-llm_prompt.py`
   - Reads `wordlist_to_llm.txt` and splits it into blocks (default: 250 words per block).
   - Sends each block to an LLM for semantic classification, using instructions in `data/prompt.txt`.
   - The LLM should classify words as relevant or not relevant for vulnerability analysis.
   - Stores results inside `relevant_words.tar`.
   - [See note about LLM usage](#llm-usage-note) for important considerations.

5. `4-classified_words.py`
   - Extracts classified words from `relevant_words.tar`.
   - Aggregates and counts the frequencies of relevant words.
   - Filters out:
     - Overly short tokens
     - Purely numeric tokens
     - Tokens with low frequency
   - Produces `unique_classified_words.txt` with token → frequency pairs.

6. `5-final_words.py`
   - Applies KneeLocator again to refine the list statistically.
   - Removes any tokens listed in `removed-words.txt`.
   - Adds any tokens from `dns-initial-keywords.txt` (must-have words).
   - Outputs `final_words.txt` — the final curated vocabulary for GT-Crivo.

## Details on 3-llm_prompt.py

This script sends batches of candidate tokens to a Large Language Model (LLM) for semantic classification to identify relevant words for vulnerability analysis.

### Connection Requirements

- You must provide a valid IP address and port number to connect to the LLM service.
- The connection URL is built as `http://<IP>:<PORT>`.
- If the script cannot connect (e.g., wrong IP/port or service offline), it will fail and return an error.

### Impact on Automation

- When running the full pipeline with `run.sh`, a failure to connect in this step will stop the entire process.
- To avoid this, you may run `3-llm_prompt.py` independently after ensuring the LLM service is accessible.

### Usage Example

```bash
python3 3-llm_prompt.py --ip 192.168.0.1 -p 5000
```

For a complete guide on how the LLM prompt works, see [LLM usage details](Running_Llama3_over_a_Distributed_GPU_Cluster.md).
