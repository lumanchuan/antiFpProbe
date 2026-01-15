# Experiment Procedure

## I. p0f Experiment

### 1. Log in to the remote hosts and start the switch program and the p0f sniffer

#### On the switch server

Go to `root/onl-bf-sde/`, open **shell1**, and run:

```bash
# Enable the BF (Tofino SDE) environment
source set_sde.bash

# Deploy the compiled P4 program to the switch
./run_switchd.sh -p antiFpProbe
```

If you see `bfshell`, the switch pipeline has started successfully.

Then go to `root/onl-bf-sde/`, open **shell2**, and run:

```bash
# Enable the BF (Tofino SDE) environment
source set_sde.bash

# Start the control-plane code
./run_p4_tests.sh -p antiFpProbe -t GXC/antiFpProbe/test_p0f/ --target tofino
```

#### On the NIC server **13122**

Open **shell1** and run:

```bash
# Start the p0f sniffer
p0f -i enp5s0f1
```

Open **shell2** and run:

```bash
# Start the iperf server
iperf -s
```

#### On the NIC server **13022**

Open **shell1** and run:

```bash
iperf -c 192.168.3.2
```

Now check **13122 shell1**: you should see the p0f output. Compare it against the OS fingerprint placed on the **switch server** under:

- `antiFpProbe/test_p0f`

If the p0f output shown on **13122 shell1** matches the fingerprint you deployed on the switch, then the disguise is successful (e.g., Linux 2.4).

---

### 2. Switch to another fingerprint

On **13122**, open:

- `p0f/p0f_db.json`

Choose the next fingerprint, e.g., `"Mac OS X:10.x"`. Copy the corresponding JSON object to the **switch server** directory:

- `antiFpProbe/test_p0f`

Remove the previous fingerprint file/object before placing the new one.

Example JSON:

```json
{
  "df": 1,
  "line_no": 216,
  "mss": 0,
  "olayout": [
    "mss",
    "nop",
    "ws",
    "nop",
    "nop",
    "ts",
    "sok",
    "eol+1"
  ],
  "os": "Mac OS X:10.x",
  "packet_size": 64,
  "raw": "*:64:0:*:65535,1:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0:Mac OS X:10.x",
  "scale": 1,
  "ttl": 64,
  "wsize": 65535,
  "wsize_raw": "65535"
}
```

---

## II. Nmap Fingerprint Anti-Scanning Experiment

### 1. Log in to the remote hosts and start the switch program

#### On the switch server

Go to `root/onl-bf-sde/`, open **shell1**, and run:

```bash
# Enable the BF (Tofino SDE) environment
source set_sde.bash

# Deploy the compiled P4 program to the switch
./run_switchd.sh -p antiFpProbe
```

If you see `bfshell`, the switch pipeline has started successfully.

Then go to `root/onl-bf-sde/`, open **shell2**, and run:

```bash
# Enable the BF (Tofino SDE) environment
source set_sde.bash

# Start the control-plane code
./run_p4_tests.sh -p antiFpProbe -t GXC/antiFpProbe/test_nmap/ --target tofino
```

If you see the message “正在进行Nmap指纹抗测绘” (Nmap fingerprint anti-scanning in progress), the setup is successful.

#### On NIC servers **13022** and **13122**

Just log in (no additional startup steps are required for this part).

---

### 2. Change the fingerprint and run the test

On **13022**, open:

- `nmap_fp/nmap_fp.json`

Copy one JSON entry from it to the **switch server** file:

- `antiFpProbe/test_nmap/fps.json`

Then on **13022**, run:

```bash
nmap -O --osscan-guess --max-os-tries 1 -p 445,80 192.168.3.2
```

Example JSON:

```json
{
  "OS": "Microsoft Windows 7",
  "ISN": {"s1":2673451493,"s2":3063823411,"s3":3358054297,"s4":3720430087,"s5":366318029,"s6":1990988521},
  "SEQ": {"SP":"250-260","GCD":"1-6","ISR":"254-264","TI":"RD","TS":"7"},
  "OPS": {"O1":[{"mss":1460},{"sack":1},{"ts":1}],"O2":[{"mss":1460},{"sack":1},{"ts":1}],"O3":[{"mss":1460},{"nop":1},{"nop":2},{"ts":1}],"O4":[{"mss":1460},{"sack":1},{"ts":1}],"O5":[{"mss":1460},{"sack":1},{"ts":1}],"O6":[{"mss":1460},{"sack":1},{"ts":1}]},
  "OPS_RAW": {"O1":"M5B4ST11","O2":"M5B4ST11","O3":"M5B4NNT11","O4":"M5B4ST11","O5":"M5B4ST11","O6":"M5B4ST11"},
  "WIN": {"W1":8192,"W2":8192,"W3":8192,"W4":8192,"W5":8192,"W6":8192},
  "ECN": {"R":"Y","DF":"Y","T":"123-133","TG":128,"W":8192,"O":[{"mss":1460},{"nop":1},{"nop":2},{"sack":1}],"O_RAW":"M5B4NNS","CC":"N","Q":""},
  "T1": {"R":"Y","DF":"Y","T":"123-133","TG":128,"S":"O","A":"O|S+","F":"AS","RD":0,"Q":""},
  "T2": {"R":"Y","DF":"Y","T":"123-133","TG":128,"W":0,"S":"Z","A":"O|S","F":"AR","O":[],"O_RAW":"","RD":0,"Q":""},
  "T3": {"R":"Y","DF":"Y","T":"123-133","TG":128,"W":0,"S":"Z","A":"O","F":"AR","O":[],"O_RAW":"","RD":0,"Q":""},
  "T4": {"R":"Y","DF":"Y","T":"123-133","TG":128,"W":0,"S":"O","A":"O","F":"R","O":[],"O_RAW":"","RD":0,"Q":""},
  "T5": {"R":"Y","DF":"Y","T":"123-133","TG":128,"W":0,"S":"Z","A":"O","F":"AR","O":[],"O_RAW":"","RD":0,"Q":""},
  "T6": {"R":"Y","DF":"Y","T":"123-133","TG":128,"W":0,"S":"O","A":"O","F":"R","O":[],"O_RAW":"","RD":0,"Q":""},
  "T7": {"R":"Y","DF":"Y","T":"123-133","TG":128,"W":0,"S":"Z","A":"O","F":"AR","O":[],"O_RAW":"","RD":0,"Q":""},
  "U1": {"DF":"N","T":"123-133","TG":128,"IPL":356,"UN":0,"RIPL":"G","RID":"G","RIPCK":"G","RUCK":"G","RUD":"G"},
  "IE": {"DFI":"N","T":"123-133","TG":128,"CD":"Z"},
  "_class": "Microsoft | Windows | 7 | general purpose",
  "_cpe": "cpe:/o:microsoft:windows_7 auto"
}
```
