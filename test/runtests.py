#!/usr/bin/env python3

import sys
import glob
import re
import subprocess

COLOR_RESET = "\u001b[0m"
COLOR_YELLOW = "\u001b[33m"
COLOR_GREEN = "\u001b[32m"
COLOR_RED = "\u001b[31m"
CARGS = {'reset': COLOR_RESET, 'yellow': COLOR_YELLOW, 'green': COLOR_GREEN, 'red': COLOR_RED}

def run_test(retrec, test):
    result = subprocess.run([retrec, test], stdout=subprocess.PIPE)
    output = result.stdout.decode("UTF-8")
    print(output.rstrip())
    failures = re.findall("(FAIL:.*)", output)
    passes = re.findall("PASS:.*", output)
    return (failures, passes)

def main():
    if len(sys.argv) != 2:
        print("Usage: {} <path/to/retrec>".format(sys.argv[0]))
        sys.exit(1)

    retrec = sys.argv[1]

    # Enumerate tests
    tests = glob.glob("*.bin")
    fails = []
    total_passes = 0
    for test in tests:
        print("--- RUNNING {} ---".format(test))
        (failures, passes) = run_test(retrec, test)
        if len(failures):
            fails += [(test, x) for x in failures]
        total_passes += len(passes)
        print("--- {}: {} failures, {} passes ---".format(test, len(failures), len(passes)))

    print("==============================")
    print("TOTAL: {red}{} failures{reset}, {green}{} passes{reset}".format(len(fails), total_passes, **CARGS))
    print("==============================")

    for fail in fails:
        print("{}: {red}{}{reset}".format(fail[0], fail[1], **CARGS))


if __name__ == "__main__":
    main()