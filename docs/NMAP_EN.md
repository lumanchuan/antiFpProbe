# Nmap Active-Fingerprint Defense: Manual Procedure

English | [简体中文](Nmap.md)

Complete [deployment](DEPLOYMENT_EN.md) first. This procedure uses Tofino1, nic-1, and nic-2. Run scans only against the experiment's traffic network.

## 1. Establish a monitoring-forwarding baseline

In Tofino1 Terminal 1, enter the project root:

```bash
bash scripts/data.sh monitor
```

Wait for device initialization. In Tofino1 Terminal 2, also from the project root:

```bash
bash scripts/control.sh monitor
```

The script verifies that the loaded configuration belongs to this checkout, checks BFRT, and rejects a duplicate control plane. The monitor is standalone source code and retains bidirectional DEV60 <-> DEV52 forwarding without depending on the old `direct_test` directory.

On nic-1:

```bash
ping -c 3 192.168.3.2
ip neigh show dev enp5s0f1
nmap -n -O --osscan-guess --max-os-tries 1 -p 445,80 192.168.3.2
```

`-n` disables reverse DNS lookup only; it does not change the OS-detection target. If ping or ARP fails, troubleshoot connectivity first. Do not use `-Pn` to conceal a genuinely broken path.

## 2. Provide one open and one closed port

Nmap OS-detection quality depends on port conditions. Check nic-2 first:

```bash
ss -lntp
```

The recommended experiment has port 80 open and port 445 closed. If port 80 has no service and you are authorized to start a temporary test service, use a new terminal on nic-2:

```bash
python3 -m http.server 80 --bind 192.168.3.2
```

Run this only from an isolated experiment directory because the HTTP server exposes files in its current directory. Stop it with Ctrl+C afterward. If port 445 already hosts a service, do not terminate it without coordinating with the device owner. Before selecting different ports, inspect the current P4 probe-matching conditions instead of changing only the Nmap command.

## 3. Switch to Nmap defense mode

Press Ctrl+C in the Tofino control-plane terminal, then stop this experiment's data plane using its normal foreground terminal or the web console's confirmed process workflow. Never use an unscoped `pkill python` or `killall bf_switchd`.

After confirming that no previous experiment process remains, run in Tofino1 Terminal 1:

```bash
bash scripts/data.sh nmap
```

In Tofino1 Terminal 2, after initialization completes:

```bash
bash scripts/control.sh nmap
```

This entry point runs the `HTML/control_plane` adapter, reuses the fingerprint logic in `test_nmap/test.py`, and emits telemetry for the web console. It can also run without opening the web interface.

## 4. Scan again and record results

On nic-1:

```bash
nmap -n -O --osscan-guess --max-os-tries 1 -p 445,80 192.168.3.2
```

Record the command, Nmap version, fingerprint JSON, reported OS, accuracy, and candidate list. A matching label is not the only acceptance condition; also verify TCP/ICMP behavior and healthy connectivity. A result produced by `--osscan-guess` is a heuristic guess, not an exact match.

## 5. Change the target fingerprint

Prefer selecting or importing JSON through the web console's Nmap profile library. The active file for this launch path is:

```text
HTML/runtime/controller_state/fps.json
```

The root-level `test_nmap/fps.json` is a first-initialization example, not the live file for this launcher. For a manual update, validate a temporary file and atomically rename it in the same directory:

```bash
cp /path/to/selected-fingerprint.json HTML/runtime/controller_state/fps.json.next
/usr/bin/python3 -m json.tool HTML/runtime/controller_state/fps.json.next >/dev/null
mv HTML/runtime/controller_state/fps.json.next HTML/runtime/controller_state/fps.json
```

The control plane validates and polls for changes. An invalid profile leaves the old rules active, and unchanged content is not reapplied. Preserve all six top-level `ISN` values; do not move them under `T1`. Valid JSON does not imply that every field can be reproduced exactly in hardware. Check the control-plane output before starting the next scan.

To use the original control-plane entry point after the data plane is ready, run `run_p4_tests.sh -p antiFpProbe -t "$PWD/test_nmap" --target tofino`. That path reads `test_nmap/fps.json` and does not emit web telemetry. Do not run it at the same time as the web adapter.

## 6. Stop

Stop any running nic-1 scan with Ctrl+C, stop the temporary HTTP service you started on nic-2, then exit the Tofino control plane before the data plane. The web console's stop-confirmation workflow affects only the switch-related processes it explicitly displays and does not stop unrelated processes on the NIC hosts.
