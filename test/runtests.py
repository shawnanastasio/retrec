#!/usr/bin/env python3

import sys
import glob
import re
import subprocess
import os
import json

COLOR_RESET = "\u001b[0m"
COLOR_YELLOW = "\u001b[33m"
COLOR_GREEN = "\u001b[32m"
COLOR_RED = "\u001b[31m"
CARGS = {'reset': COLOR_RESET, 'yellow': COLOR_YELLOW, 'green': COLOR_GREEN, 'red': COLOR_RED}

def run_test(retrec, test):
    env_path = os.path.dirname(test) + "/." + os.path.basename(test) + ".env"
    if os.path.isfile(env_path):
        with open(env_path) as f:
            env = json.load(f)
    else:
        env = None

    failures = []
    passes = []

    result = subprocess.run([retrec, test], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    try:
        output = result.stdout.decode("UTF-8")
    except Exception as e:
        failures.append("Unable to parse program output: {}".format(e))
        return (failures, passes)

    print(output.rstrip())

    failures += re.findall("(FAIL:.*)", output)
    passes += re.findall("PASS:.*", output)

    if result.returncode != 0:
        failures.append("Process exited with code {}".format(result.returncode))
        return (failures, passes)

    expected_results_path = os.path.dirname(test) + "/." + os.path.basename(test) + ".expected"
    if os.path.isfile(expected_results_path):
        # Compare output to expected
        with open(expected_results_path, "r") as f:
            expected = f.read()

        if output != expected:
            failures.append("Output doesn't match {}".format(expected_results_path))

    return (failures, passes)

def main():
    if len(sys.argv) != 2:
        print("Usage: {} <path/to/retrec>".format(sys.argv[0]))
        sys.exit(1)

    retrec = sys.argv[1]

    # Enumerate tests
    tests = glob.glob("**/*.bin")
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
