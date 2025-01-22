# Zeek QUIC Log Analyzer

A Python script that analyzes Zeek QUIC logs to detect potential Merlin C2 fingerprints.

## Requirements
- Python 3.x
- ipaddress package (`pip install ipaddress`)

## Usage

1. Place your Zeek QUIC log files in the `input` directory, note example sets are included. 
2. Rename your log files to include meaningful labels (e.g., `dataset1.log`, `malicious.log`)
3. Run the script: `python main.py`

The script will analyze each .log file and output results to both the terminal and `results.txt`.

## Customization

You can modify the Merlin fingerprints being detected by adjusting line 7 in the code:

```python
self.merlin_fingerprints = ["ISishIH", "IShisIH"]
```