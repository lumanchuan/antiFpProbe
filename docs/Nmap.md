# Nmap 主动指纹对抗：手动操作

[English](NMAP_EN.md) | 简体中文

先完成 [部署](部署.md)。本节涉及 Tofino1、nic-1、nic-2，所有扫描仅针对本实验业务网段。

## 1. 先跑监测转发基线

Tofino1 终端 1，进入项目根目录：

```bash
bash scripts/data.sh monitor
```

等设备完成初始化。Tofino1 终端 2，同样进入项目根目录：

```bash
bash scripts/control.sh monitor
```

脚本先确认运行配置属于这个目录，再检查 BFRT，拒绝重复控制面。监测程序是独立源代码，保留 DEV60 ↔ DEV52 双向转发，不需要旧 `direct_test` 目录。

nic-1：

```bash
ping -c 3 192.168.3.2
ip neigh show dev enp5s0f1
nmap -n -O --osscan-guess --max-os-tries 1 -p 445,80 192.168.3.2
```

`-n` 仅关闭 DNS 反向查询，不改变 OS 探测目标。若 ping/ARP 不通，应先排查网络；不能用 `-Pn` 把真正不通的链路掩盖成正常。

## 2. 保证一个开放端口、一个关闭端口

Nmap OS 探测质量依赖端口条件。nic-2 先检查：

```bash
ss -lntp
```

推荐实验条件：80 开放、445 关闭。若 80 没有服务且允许启动临时测试服务，在 nic-2 新终端运行：

```bash
python3 -m http.server 80 --bind 192.168.3.2
```

只在隔离实验目录运行，HTTP 服务会公开当前目录内容，不要从包含私密文件的目录启动。用完 Ctrl+C 退出。若 445 已有业务服务，不要擅自杀掉，应与设备使用者协调。采用其他端口前也应检查现有 P4 探针匹配条件，而不是只改 nmap 命令。

## 3. 切到 Nmap 抗测绘

先在 Tofino 控制面终端 Ctrl+C 退出控制面，再停止该实验的数据面。可使用原数据面终端的正常退出方式，或在网页确认进程后停止。切勿使用无范围 `pkill python`/`killall bf_switchd`。

确认没有旧实验进程后，Tofino1 终端 1：

```bash
bash scripts/data.sh nmap
```

Tofino1 终端 2，等待初始化完成：

```bash
bash scripts/control.sh nmap
```

本入口运行 `HTML/control_plane` 适配器，复用 `test_nmap/test.py` 的指纹逻辑，并输出网页可读取的遥测。即使不打开网页也能手动运行。

## 4. 再次扫描并记录

nic-1：

```bash
nmap -n -O --osscan-guess --max-os-tries 1 -p 445,80 192.168.3.2
```

保存命令、Nmap 版本、指纹 JSON、OS 结果、准确度/候选列表。目标标签相同不是唯一验收条件，还应确认 TCP/ICMP 行为和链路没有异常。`--osscan-guess` 给出的猜测不是精确匹配。

## 5. 更换目标指纹

推荐在网页 Nmap 指纹库中选择或导入 JSON。手动运行时，当前活动文件是：

```text
HTML/runtime/controller_state/fps.json
```

根目录 `test_nmap/fps.json` 是首次初始化样例，不是本启动脚本的实时活动文件。替换时先写临时文件并检查 JSON，再在同一目录原子改名：

```bash
cp /path/to/selected-fingerprint.json HTML/runtime/controller_state/fps.json.next
/usr/bin/python3 -m json.tool HTML/runtime/controller_state/fps.json.next >/dev/null
mv HTML/runtime/controller_state/fps.json.next HTML/runtime/controller_state/fps.json
```

控制面会校验并轮询加载；无效指纹保留旧规则，只有内容变化才更新。顶层 `ISN` 的六个数需要保留，不能误放到 `T1` 内。JSON 语法正确不代表所有字段都可被硬件精确仿真，先观察控制面输出，再开始下一次扫描。

若需要完全按原控制面入口运行，可在完成数据面准备后手动调用 SDE 的 `run_p4_tests.sh -p antiFpProbe -t "$PWD/test_nmap" --target tofino`；这时读取的是 `test_nmap/fps.json`，不会自动提供网页遥测。不要与网页适配器同时运行。

## 6. 停止

Ctrl+C 停止 nic-1 扫描（如仍运行）；停止自己启动的 nic-2 临时 HTTP 服务；先退出 Tofino 控制面，再退出数据面。网页提供的停止确认流程只针对明确显示的交换机相关进程，不会停止 NIC 上的其他实验。
