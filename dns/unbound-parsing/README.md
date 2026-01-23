# Unbound DNS Log Analysis

This project processes anonymized Unbound DNS logs to generate usage statistics and visualizations.  It consists of a high-performance Rust parser for log processing and Python scripts for generating graphs.

## Overview

The workflow consists of two main steps:

1.  **Rust Parser (`unbound-parsing`)**: Reads gzip-compressed logfiles, parses them using regular expressions, and aggregates statistics into CSV files.

2.  **Python Plotters (`scripts/`)**: Read the generated CSV metrics and produce weekly time-series and Zipf distribution graphs in PNG and PDF formats.

## Quick Start

Run the following commands to process logs and generate all graphs. Replace `/home/datasets/dnssync` with the actual path to your logfiles.

```bash
RUST_LOG=info cargo run --release -- --log-dir /home/datasets/dnssync
cd scripts
uv run plot_timeseries.py
uv run plot_zipf.py
```

All results are saved in the `output/` directory by default.
