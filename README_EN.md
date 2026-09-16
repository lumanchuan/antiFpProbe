# OSDisguise: Operating-System Fingerprint Defense on a Programmable Switch

English | [简体中文](README.md)

OSDisguise processes responses to active Nmap probes and TCP fingerprints observed passively by p0f. It runs on a **Tofino1 hardware switch with Barefoot SDE 9.7.0 and P4_16**, and includes a web console for selecting fingerprints, switching modes, and viewing telemetry.

This repository is a reproducible competition and source-code release. The directory can be renamed or moved because the source does not depend on the original installation path. A first-time deployment requires compatible hardware, a legally obtained SDE installation, and the documented Python dependencies. The Tofino data plane cannot run on a regular computer.

## Start here

1. [Deployment and environment checks](docs/DEPLOYMENT_EN.md): the three hosts, cabling, software, initialization, compilation, and diagnostics.
2. [Nmap procedure](docs/NMAP_EN.md): forwarding baseline, active fingerprint defense, scanning, and changing fingerprints.
3. [p0f procedure](docs/P0F_EN.md): passive fingerprint defense, packet observation, iperf2 traffic, and acceptance checks.
4. [Web console](docs/HTML_EN.md): installing the web environment, starting and stopping services, switching modes, and connecting the sensor.
5. [Architecture, limitations, and troubleshooting](docs/ARCHITECTURE_AND_TROUBLESHOOTING_EN.md): hardware readiness versus end-to-end connectivity, DPDK, Python ABI issues, and recognition boundaries.
6. [Release and provenance notes](docs/RELEASE_NOTES_EN.md): Apache-2.0 scope, third-party notices, and sanitized source exports.
7. [Validation record](docs/VALIDATION_EN.md): what was actually tested and what remains environment-specific.

## Repository layout

```text
.
├── README.md / README_EN.md / LICENSE / NOTICE / .gitignore
├── antiFpProbe.p4                 # Nmap/p0f compile-time selector
├── nmap_tofino.p4                 # Nmap data plane
├── p0f_tofino.p4                  # p0f data plane
├── common/                        # Shared headers; original notices retained
├── configs/                       # Example forwarding and ARP rules
├── config/deployment.example.json # Deployment configuration example
├── test_nmap/                     # Nmap control plane and initial profile
├── test_p0f/                      # p0f control plane, normalization, examples
├── monitor/scan_monitor/          # Standalone monitoring-forwarding mode
├── HTML/                          # Web app, adapters, sensor, profile libraries
├── scripts/                       # Configuration, build, checks, launch, export
├── tests/                         # Nmap unit tests
└── docs/                          # Chinese and English documentation
```

`build/`, `HTML/runtime/`, `.venv/`, and `config/deployment.json` are generated locally after deployment and are not public source files. A clean checkout contains no previous tokens, databases, logs, packet captures, or SSH keys.

## Quick start

Run the following commands from the project root on **Tofino1**. `SDE` must point to the locally installed SDK; the example path is not an installer.

```bash
export SDE=/root/bf-sde-9.7.0
python3 scripts/configure.py --sde "$SDE"

# PLATFORM_CONFIG must be a working hardware configuration for this switch.
export PLATFORM_CONFIG="$SDE/install/share/p4/targets/tofino/antiFpProbe.conf"
/usr/bin/python3 scripts/build.py all --platform-config "$PLATFORM_CONFIG"
/usr/bin/python3 scripts/doctor.py
```

The `PLATFORM_CONFIG` path above is an example from the original testbed. On another machine, select an existing SDE configuration that is already known to drive that physical switch. Its program name does not need to be `antiFpProbe`. The builder reads only the hardware portion, does not copy the old P4 program, and does not overwrite the SDE installation.

For manual operation, open two terminals on Tofino1 and run the commands from the project root:

```bash
# Terminal 1: choose monitor, nmap, or p0f
bash scripts/data.sh nmap
```

```bash
# Terminal 2: wait for Terminal 1 to initialize, then use the same mode
bash scripts/control.sh nmap
```

See [HTML_EN.md](docs/HTML_EN.md) for the web console. Starting the web service does not automatically load a switch program. Every mode change presents the current process list and requires confirmation.

## Experimental scope

- Default traffic path: nic-1 `192.168.3.1` -> Tofino -> nic-2 `192.168.3.2`.
- Nmap runs on nic-1 and scans nic-2. p0f runs on nic-2 and observes TCP SYN packets sent by nic-1. These experiments observe different endpoints.
- The three modes share one ASIC and must be loaded serially. Nmap and p0f are compiled and cached separately; changing a fingerprint does not require recompilation.
- The profile directories contain existing examples and candidate records. Passing schema validation does not prove that every version has passed an end-to-end hardware test. Runtime compatibility checks remain enabled.
- Run scans, packet capture, and traffic experiments only on networks you own or are authorized to test.

## License

Author-owned code and the deployment scripts and documentation added for this release use the **Apache License 2.0**; see [LICENSE](LICENSE). Third-party files are not automatically relicensed under Apache-2.0. See [NOTICE](NOTICE) and [RELEASE_NOTES_EN.md](docs/RELEASE_NOTES_EN.md). The provenance and redistribution rights of the shared SDK helper and fingerprint data still require confirmation by the publisher, so this repository must not be described as having completed a legal review of every file.
