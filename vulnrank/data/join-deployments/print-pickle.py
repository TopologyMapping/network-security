#!/usr/bin/env python3
import pickle
import sys
import pprint

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <pickle_file>")
    sys.exit(1)

pickle_file = sys.argv[1]

with open(pickle_file, 'rb') as f:
    data = pickle.load(f)
    pprint.pprint(data)
