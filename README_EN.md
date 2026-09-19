<p align="center">
  <img src="./HTML/static/images/testbed-gateway.png" width="760" alt="OSDisguise programmable-switch testbed">
</p>

<h1 align="center">OSDisguise</h1>

<p align="center">
  <strong>Disguising operating-system fingerprints in the programmable data plane</strong><br>
  Transparent, line-rate, subnet-wide protection against active Nmap scans and passive p0f identification
</p>

<p align="center">
  <strong>English</strong> ·
  <a href="README.md">简体中文</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#system-architecture">Architecture</a> ·
  <a href="#documentation">Documentation</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/P4-16-0066CC?style=for-the-badge" alt="P4 16">
  <img src="https://img.shields.io/badge/Intel_Tofino-1-00A88F?style=for-the-badge" alt="Intel Tofino1">
  <img src="https://img.shields.io/badge/Throughput-100_Gbps-7C3AED?style=for-the-badge" alt="100 Gbps">
  <img src="https://img.shields.io/badge/Defense-Nmap_%7C_p0f-EF4444?style=for-the-badge" alt="Nmap and p0f">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/lumanchuan/antiFpProbe?style=for-the-badge" alt="License"></a>
</p>

---

OSDisguise moves operating-system fingerprint deception from protected hosts into the network data plane. On **Intel Tofino1 / Barefoot SDE 9.7.0 / P4_16**, it classifies fingerprint probes, reconstructs IP/TCP fields and TCP Options according to a target policy, and inserts temporally consistent Initial Sequence Numbers (ISNs). Protected hosts require no kernel patches, Netfilter modules, or resident agents.

> Results reported in the paper: evaluated with thousands of real OS fingerprints, OSDisguise reaches **92.48%** average disguise success against Nmap and **85.97%** against p0f while sustaining **100 Gbps** line-rate forwarding.

| **92.48%** | **85.97%** | **100 Gbps** | **Subnet-wide** |
|:---:|:---:|:---:|:---:|
| Nmap average success | p0f average success | Tofino1 line rate | One switch protects a subnet |

## Why OSDisguise

OS fingerprinting is an important reconnaissance step before exploitation. Scanners combine TTL, TCP window sizes, flags, option order, fragmentation behavior, and cross-packet ISN evolution to infer the target OS. Host-side defenses require per-host deployment and consume CPU, kernel, and NIC resources; simply dropping probes also produces behavior unlike a normal network stack.

OSDisguise decomposes the fingerprinting semantics into data-plane-friendly operations:

| Mechanism | Role |
|---|---|
| **Recirculation parser** | Extends fixed parsing depth to recognize variable-length TCP Options and probe types. |
| **Multi-slot option construction** | Rebuilds MSS, SACK, Timestamp, Window Scale, and their ordering through programmable slots. |
| **ISNG algorithm** | Generates ISN sequences satisfying GCD, ISR, and SP constraints offline; the data plane only looks them up and inserts them. |
| **Match-action disguise** | Selects a policy by protected host, probe, and target OS, then rewrites fields, repairs lengths, and updates checksums. |

## System architecture

### Active fingerprint deception - Nmap / Xprobe2

An active scanner sends crafted probes to a protected host. The switch performs recirculation-based TCP Option parsing, probe classification, policy lookup, response synthesis, and ISN insertion before returning a response that carries the target OS fingerprint.

<p align="center">
  <img src="./docs/assets/osdisguise-active-workflow.svg" width="100%" alt="OSDisguise active fingerprint workflow">
</p>

### Passive fingerprint deception - p0f

A passive observer infers the source OS from ordinary TCP traffic without sending probes. OSDisguise matches packets in the forwarding path, applies the selected fingerprint policy, and repairs checksums so observed SYN features are decoupled from the real host.

<p align="center">
  <img src="./docs/assets/osdisguise-passive-workflow.svg" width="100%" alt="OSDisguise passive fingerprint workflow">
</p>

The paper evaluates Nmap, p0f, and Xprobe2. The public testbed release focuses on **active Nmap mode, passive p0f mode, and a standalone monitoring-forwarding mode**.

## What this repository provides

| Mode | Data plane | Control plane | Purpose |
|---|---|---|---|
| `monitor` | `monitor/scan_monitor/scan_monitor.p4` | `monitor/scan_monitor/controller.py` | Forwards production traffic and counts Nmap probes without changing fingerprints. |
| `nmap` | `nmap_tofino.p4` | `test_nmap/test.py` | Recognizes active probes and synthesizes target-OS responses. |
| `p0f` | `p0f_tofino.p4` | `test_p0f/test.py` | Rewrites ordinary TCP SYN packets so passive observation reports a target OS. |
| Web console | `HTML/` | Flask + BFRT adapters | Manages modes, profiles, process confirmation, link state, and scan telemetry. |

Default testbed path:

```text
nic-1 (192.168.3.1)  -- DEV_PORT 60 -->  Tofino1  -- DEV_PORT 52 -->  nic-2 (192.168.3.2)
       scanner / client                  P4 data plane               protected host / observer
```

All three modes share one ASIC and must be loaded serially. Nmap and p0f are compiled and cached separately; changing a fingerprint updates table entries without recompiling P4.

## Quick start

> Requires Tofino1 hardware, a legally installed Barefoot SDE 9.7.0, and a platform configuration known to drive the switch. The data plane cannot run on a regular computer.

Run from the project root on **Tofino1**:

```bash
export SDE=/root/bf-sde-9.7.0
python3 scripts/configure.py --sde "$SDE"

# Replace this with a hardware configuration verified on your switch.
export PLATFORM_CONFIG="$SDE/install/share/p4/targets/tofino/antiFpProbe.conf"
/usr/bin/python3 scripts/build.py all --platform-config "$PLATFORM_CONFIG"
/usr/bin/python3 scripts/doctor.py
```

Open two Tofino terminals. Start the data plane first, then the control plane for the same mode:

```bash
# Terminal 1: monitor, nmap, or p0f
bash scripts/data.sh nmap
```

```bash
# Terminal 2: wait until Terminal 1 finishes device initialization
bash scripts/control.sh nmap
```

See [Deployment](docs/DEPLOYMENT_EN.md) for compilation, ports, NIC kernel-driver recovery, and connectivity checks. See [Web console](docs/HTML_EN.md) for service start and stop procedures.

## Documentation

| Document | Coverage |
|---|---|
| [Deployment and environment checks](docs/DEPLOYMENT_EN.md) | Three hosts, cabling, SDE, initialization, compilation, and diagnostics. |
| [Nmap experiment](docs/NMAP_EN.md) | Monitoring-forwarding, active disguise, scanning, and profile switching. |
| [p0f experiment](docs/P0F_EN.md) | Passive disguise, sensor, iperf2 traffic, and acceptance checks. |
| [Web console](docs/HTML_EN.md) | Service management, mode conflicts, telemetry, and profile libraries. |
| [Architecture and troubleshooting](docs/ARCHITECTURE_AND_TROUBLESHOOTING_EN.md) | DPDK/kernel drivers, Python ABI, link readiness, and end-to-end reachability. |
| [Validation record](docs/VALIDATION_EN.md) | Automated tests, compilation, and hardware validation scope. |
| [Release and provenance](docs/RELEASE_NOTES_EN.md) | License boundaries, third-party notices, and sanitized exports. |

<details>
<summary><strong>Repository layout</strong></summary>

```text
.
├── antiFpProbe.p4                 # Nmap / p0f compile-time selector
├── nmap_tofino.p4                 # Active fingerprint-disguise data plane
├── p0f_tofino.p4                  # Passive fingerprint-disguise data plane
├── common/                        # Shared P4 headers
├── configs/                       # Example IPv4 and ARP rules
├── test_nmap/                     # Nmap control plane and initial profile
├── test_p0f/                      # p0f control plane, normalization, examples
├── monitor/scan_monitor/          # Standalone monitoring-forwarding mode
├── HTML/                          # Web app, adapters, sensor, profile libraries
├── scripts/                       # Configuration, build, checks, launch, export
├── tests/                         # Control-plane unit tests
└── docs/                          # Chinese and English documentation
```

`build/`, `HTML/runtime/`, `.venv/`, and `config/deployment.json` are private deployment outputs and are excluded from source control.

</details>

## Paper

**OSDisguise: Disguising OS Fingerprints Against Network Scanning in the Data Plane**<br>
Xiaochuan Guo, Kun Xie, Ke Xu, Xin Zeng, Ziyang Peng, Jigang Wen, Yanbiao Li, Xiaocan Li, Guangxing Zhang, and Gaogang Xie.

The full evaluation also covers Xprobe2, ablation studies, resource consumption, throughput, and scalability to thousands of protected hosts. This repository reproduces the public Tofino1, Nmap, p0f, monitoring, and web-console workflows.

## Scope and license

- Run scanning, packet capture, and traffic experiments only on networks you own or are authorized to test.
- Passing profile-schema validation does not prove that every OS version has passed an end-to-end hardware test; runtime compatibility checks remain enabled.
- Author-owned code, deployment scripts, and documentation use the [Apache License 2.0](LICENSE). Third-party files are not automatically relicensed; see [NOTICE](NOTICE) and [release notes](docs/RELEASE_NOTES_EN.md).

<p align="center"><sub>Research prototype for authorized network-defense experiments.</sub></p>
