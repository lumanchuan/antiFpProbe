# Reproducibility-Package Validation Record

English | [简体中文](验证记录.md)

Preparation date: 2026-09-15. Validation platform: Tofino1 host with SDE 9.7.0. The original project remained unchanged. Initialization, dependency installation, compilation, and web startup tests ran in a separate temporary copy whose directory name differed from the handoff directory.

## Completed checks

| Check | Result |
|---|---|
| Nmap control-plane unit tests | 17 passed |
| p0f profile-normalization unit tests | 6 passed |
| Web, process-management, sensor-isolation, and relocation regression tests | 60 passed |
| Independent Nmap P4 build | Passed; generated BFRT schema, context, tofino.bin, and standalone configuration |
| Independent p0f P4 build | Passed; outputs separated from Nmap |
| Independent scan_monitor P4 build | Passed; no include dependency on the former direct_test directory |
| doctor diagnostics | SDK/Python ABI, all three configurations, and active examples passed |
| Python/shell syntax | Key SDE scripts checked with Python 3.5; web/tools with Python 3.9; shell scripts with bash -n |
| Web pages and static assets | Gateway, Nmap, p0f, and all referenced local assets responded successfully |
| APIs | Login, Nmap/p0f profile lists, and runtime state passed without exposing tokens |
| Real web start/stop | Started on a random loopback port, served HTTP, and the manager stopped only its own process |
| p0f sensor bundle | Generated in memory and checked for compilable code; not executed on a NIC host |
| Conservative source archive | Exported successfully without runtime, build, tokens, or the unconfirmed SDK helper |
| Original-file preservation | SHA-256 hashes of 107 initially selected files matched the original project |
| Handoff cleanliness | No runtime database, token, SSH key, old build binary, temporary directory name, or original absolute project path |

A total of **83 unit and regression tests passed**. The Nmap test suite intentionally injects an RPC failure and invalid JSON to verify rollback and retention of the old rules. Related exception messages in test output are expected test cases, not a real hardware deployment failure.

The web profile directories contain 47 Nmap records and 10 p0f records. Compatibility checks still restrict incompatible records. These counts are directory/API checks and do not claim that every record passed a hardware recognition experiment.

## Compiler warnings

The Nmap build retains original warnings about table-size reduction when the available match-bit width supports fewer entries than declared. It also retains a compiler substitution warning for an ICMP key slice. The p0f build retains a key-name substitution warning for the `plain_syn` flags slice. All three builds returned success, and the monitoring-forwarding build did not emit those warnings. The algorithms were not rewritten merely to suppress warnings.

## Not performed in that validation run

- No new P4 pipeline was loaded or switched on the ASIC.
- The existing port-5080 service, original data/control planes, and NIC processes were not stopped.
- NIC drivers, IP addresses, routes, ARP, firewall, and SSH settings were not modified.
- Every Nmap/p0f fingerprint was not re-run through a hardware recognition and TCP traffic experiment.
- Third-party rights did not receive a legal review.

This record demonstrates that the package builds independently, survives directory relocation, and has working control logic and web deployment paths. It does not guarantee exact emulation of every profile on a new environment. Before a formal demonstration, run the Nmap and p0f end-to-end procedures and record the software versions, selected profile, packet observations, and detector result.

## Re-run commands

After configuration, build, and installation of the isolated web environment, run from the project root:

```bash
/usr/bin/python3 -m unittest discover -s tests
/usr/bin/python3 -m unittest discover -s test_p0f -p test_profile_unit.py
.venv/bin/python -m unittest discover -s HTML/tests -p 'test_*.py'
/usr/bin/python3 scripts/doctor.py
```

The tests create isolated temporary data under this checkout's `HTML/runtime`. To avoid sharing runtime state with an active demonstration entirely, initialize and test a separate copy. Process-stop tests affect only disposable processes created by the tests themselves.
