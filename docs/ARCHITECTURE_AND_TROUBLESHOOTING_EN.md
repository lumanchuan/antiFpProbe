# Architecture, Limitations, and Troubleshooting

English | [简体中文](架构与排障.md)

## Data and control paths

```text
nic-1 (.3.1, DEV60) <---- Tofino1 ASIC ----> nic-2 (.3.2, DEV52)
                               ^
                    BFRT / local control plane
                               ^
          Flask console (profiles, process confirmation, telemetry)
                               ^
              nic-2 p0f sensor (dedicated token, heartbeat)
```

- `antiFpProbe.p4` selects the Nmap or p0f source. Each mode is built separately, so switching does not require editing this file.
- `test_nmap/test.py` retains the original active-defense rules, ISN handling, TCP options, and hot profile updates.
- `test_p0f/test.py` and `p0f_profile.py` retain the original passive-fingerprint processing and parameter normalization.
- `HTML/control_plane` and `HTML/p0f_control` are web adapters. They reuse the modules above while adding telemetry, separate active-profile paths, and pipeline-run identities.
- `monitor/scan_monitor` supplies monitoring-forwarding without fingerprint rewriting and brings the former external dependency into the project.
- `scripts/build.py` only compiles and generates local configurations. `scripts/data.sh` and `scripts/control.sh` provide checked manual startup, while the web console performs user-confirmed switching.

## "Host seems down" or ping failure

The Nmap `mass_dns` message is only a DNS warning and does not explain complete ping loss. Check, in order, whether `enp5s0f1` exists on both hosts, whether the kernel owns its driver, whether the traffic IP remains configured, whether the route uses that interface, whether ARP resolves, whether both switch ports are UP, and whether the DEV mapping matches the cabling.

A common cause is another throughput experiment binding the NIC to DPDK. The switch ports and control-plane readiness can still look healthy while Linux cannot use the traffic interface. Coordinate with the device owner before restoring the driver and addresses. This package does not automatically rebind the NIC or write network configuration.

The page's link-ready state confirms stable hardware port status. It does not prove end-to-end reachability between the two Linux hosts. `doctor.py` also does not modify NIC hosts through unrestricted SSH. Use `ip`, `ethtool`, and `ping` on the hosts to validate the actual path.

## p4testutils missing from a Python directory

An error such as `install/lib/python3.10/site-packages/p4testutils/... not found` usually means that an incompatible Conda environment is active, causing the launcher to look for Python 3.10 components while this SDE installed them for Python 3.5.

Control-plane launchers clear `PYTHONHOME` and `PYTHONPATH` and prefer `/usr/bin`. The web app uses an independent `.venv`. Do not copy binary extensions from another Python ABI into the missing directory. When changing SDE versions, verify its supported Python and BFRT/PTF dependencies again.

## Switch failure or PID does not exit

Before and after confirmation, the web console checks PID, process start time, and command line. It does not issue an unconditional SIGKILL or kill an entire process group. If a process remains, inspect `HTML/runtime/control.log` and `HTML/runtime/data.log` and identify the specific blockage before retrying.

An expired confirmation, changed process list, or reused PID requires a new prepare-and-confirm cycle. Missing build files are reported before the current program is stopped. Manual launch scripts reject an existing data plane and never stop another user's process automatically.

## Does an OS label prove success?

No. Distinguish a candidate profile, schema validation, control-plane deployment, packet-field agreement, detector recognition, and a working application connection. Nmap timestamp clocks, IP-ID sequences, and some U1 fields still have coverage limitations. Some p0f targets without TCP timestamps are incompatible with the current precompiled path.

Two variants with the same OS name are not equivalent to two successful experiments. For a competition demonstration, use only profiles that you have retested end to end and recorded. Do not convert compatibility warnings into success states merely to increase the displayed count.

## Web statistics and clocks

Nmap detection counts come from hardware-rule matches, and session count is an aggregate estimate. p0f is passive and obtains its primary signature only from new TCP handshakes. Keep host clocks reasonably synchronized or timeline events can appear shifted. This package does not change system time.

## Shutdown and rollback

The source release does not overwrite the original project or installed SDE build outputs. If the new demonstration fails, explicitly exit its control plane and data plane before returning to the known original workflow. Never run control planes from both directories at once. Stopping the web service alone does not change the program currently loaded in the ASIC.
