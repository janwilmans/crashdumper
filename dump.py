"""Crash dump analysis using kd
"""
from __future__ import print_function

import os, sys, re, subprocess, glob
import traceback, json

# print to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def wipeLinesInclusive(content, needle):
    lineNr = 0
    for line in content: 
        lineNr = lineNr + 1
        if needle in line:
            break
    return content[lineNr:]
    
def extractInfoFromCrashdump(filename):
    sub_env = os.environ.copy()
    sub_env["_NT_SYMBOL_PATH"] = "srv*c:\Symbols*http://msdl.microsoft.com/download/symbols;."
    cmd = ['d:\msdbg\kd.exe', '-z', filename, '-c', 'ld *;!peb;!dlls;!runaway 4;!uniqstack;q'] # ; !analyze -v
    proc = subprocess.Popen(cmd, env=sub_env, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc.stdout.readlines()

# filter the output of the !peb command (process environment block)
def filterPeb(content):
    t1 = wipeLinesInclusive(content, "PEB at")
    t1 = wipeLinesInclusive(t1, "Base TimeStamp                     Module")
    result = []
    for line in t1[:20]:
        result += [line]
    return result

def utfDecode(content): 
    if sys.version_info[0] < 3:
        result = []
        for line in content: 
            result += [line.strip()]
        return result

    # decode('utf-8') for python 3+ only
    result = []
    for line in content: 
        result += [line.decode('utf-8').strip()]
    return result

def cleanup(text):
    return text.strip('\'" \n')

def simpleAdd(result, line, needle):
    if needle in line.lower():
        cols = line.split(":")
        if len(cols) > 1:
            result += [ [ cleanup(cols[0]), cleanup(":".join(cols[1:])) ] ] 
        else:
            result += [ [ line, None ] ]

def filterInfo(content):
    result = []
    for line in content:
        simpleAdd(result, line, "commandline")
        simpleAdd(result, line, "machine")
        simpleAdd(result, line, "time:")
        simpleAdd(result, line, "dllpath:")
    return result

def analyze(filename):
    info = utfDecode(extractInfoFromCrashdump(filename))
    #for l in info:
    #    print (l)
    print ("--- Summary ---\n\n")
    print ("Process information:")
    for e in filterInfo(info):
        print (e)
    
    print ("\nLoaded modules:")
    for e in filterPeb(info):
        print (e)

def getFiles(mask):

    if os.path.isfile(mask):
        return [mask]
    
    if os.path.isdir(mask):
        result = []
        for root, dirs, files in os.walk(mask, topdown=False):
            for name in files:
                if name.endswith(".dmp"):
                    result += [os.path.join(root, name)]
        return result

    # otherwise assume is a filespec mask like *.dmp
    return glob.glob(mask)
    
def getRealFiles(mask):
    return [ os.path.realpath(filename) for filename in getFiles(mask) ] 

def main2():
    if len(sys.argv) < 2:
        print("Usage: dump.py <dir\filemask>")
        print("  ex: dump.py foo.dmp")
        print("  ex: dump.py foo\*.dmp")
        print("  ex: dump.py foo\  # will do a recursive scan for *.dmp")
        sys.exit(1)

    for filename in getRealFiles(sys.argv[1]):
        analyze(filename)

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

