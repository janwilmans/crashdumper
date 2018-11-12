"""Crash dump analysis using kd
"""
from __future__ import print_function

import os, sys, re, subprocess, glob
import traceback, json

# print to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def getStdinLines():
    lines = []
    for line in sys.stdin:
        lines += [line.strip()]
    return lines

def main2():
    if len(sys.argv) < 2:
        print("Usage: filter.py <needle>")
        sys.exit(1)

    for line in getStdinLines():
        if sys.argv[1] in line:
            print(line)

def main():
    try:
        main2()
    except SystemExit as e:
        sys.exit(e)
    except:
        info = traceback.format_exc()
        eprint(info)

if __name__ == "__main__":
    main()
    sys.exit(0)

