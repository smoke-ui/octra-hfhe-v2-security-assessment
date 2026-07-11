#!/usr/bin/env python3
"""Run one fault scenario quietly and report its conventional shell status."""

import os
import subprocess
import sys

scenario, preload, driver = sys.argv[1:]
environment = os.environ.copy()
environment["ENTROPY_FAULT_SCENARIO"] = scenario
environment["LD_PRELOAD"] = preload
completed = subprocess.run(
    [driver],
    env=environment,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    check=False,
)
status = completed.returncode
if status < 0:
    status = 128 - status
print(status)
