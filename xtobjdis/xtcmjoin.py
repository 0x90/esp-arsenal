#!/usr/bin/python3

# This is just a very simple script to join multiple callmaps (as produced by
# xtobjdis' --callmap option) into a single callmap file.
#
# Usage: xtcmjoin FILE [FILE ...] > OUTFILE

import sys
import json

result = []
for filename in sys.argv[1:]:
    with open(filename, 'r') as f:
        mapdata = json.load(f)
    result.extend(mapdata)

json.dump(result, sys.stdout, sort_keys=True, indent=4)
