# p0f 被动指纹对抗：手动操作

[English](P0F_EN.md) | 简体中文

先完成 [部署](部署.md)。与 Nmap 不同，本实验由 **nic-1 发起 TCP 连接，nic-2 的 p0f 观察客户端 SYN**。p0f 不主动扫描；nic-2 自己发出的 SYN-ACK 不是本模式的客户端伪装对象。

## 1. Tofino1 启动数据面

如果刚做完 Nmap，先停止旧控制面和旧数据面，或通过网页切换确认流程结束它们。不能同时运行两个 `antiFpProbe` 控制面。

Tofino1 终端 1，进入项目根目录：

```bash
bash scripts/data.sh p0f
```

该命令使用 `build/p0f/antiFpProbe_p0f.conf`，不会误用 Nmap 的编译结果。

## 2. Tofino1 启动控制面

Tofino1 终端 2，进入项目根目录，等待终端 1 初始化后运行：

```bash
bash scripts/control.sh p0f
```

检查输出中的 `P0F_READY`、目标系统及端口状态。控制面启动不代表 Linux 业务链路必然联通，仍需核对两端网卡和地址。

## 3. nic-2 启动 p0f

nic-2 终端 1：

```bash
p0f -i enp5s0f1 'tcp port 5001'
```

看到进入主事件循环后等待流量。这是正常监听状态，没有新 TCP 握手时不会出现新的系统识别。需要 root 或相应抓包能力。

## 4. nic-2 启动 iperf2 服务

nic-2 终端 2：

```bash
iperf -s -B 192.168.3.2 -p 5001
```

如果端口已经有人使用，先查 `ss -lntp`，不要直接终止别人的服务。这里必须使用 iperf2。

## 5. nic-1 产生新连接

nic-1：

```bash
iperf -c 192.168.3.2 -p 5001 -t 10 -b 1M -l 1024
```

检查两部分结果：

1. nic-2 的 p0f 显示源 `.3.1` → 目的 `.3.2`、`syn` 方向的 OS/原始签名，与当前活动指纹相符。
2. iperf 客户端及服务端均有实际传输结果。只有 p0f 显示某个名字、但 TCP 连接失败，不能记为成功。

若需要严格验收，使用 tcpdump 保存接收侧握手包并核查 TCP/IP 校验和、TTL、窗口、选项布局；注意抓包点的网卡 checksum offload 可能影响校验显示，不能单凭发送端提示下结论。

## 6. 更换指纹

网页 p0f 指纹库提供选择、导入和当前下发状态。手动入口使用：

```text
HTML/runtime/p0f_state/fps.json
```

可选样例在 `test_p0f/examples/`，已有指纹目录在 `HTML/profiles_p0f/`。同名系统可能是不同签名变体，不代表不同版本都经过验证。

```bash
cp /path/to/selected-p0f.json HTML/runtime/p0f_state/fps.json.next
/usr/bin/python3 -m json.tool HTML/runtime/p0f_state/fps.json.next >/dev/null
mv HTML/runtime/p0f_state/fps.json.next HTML/runtime/p0f_state/fps.json
```

等待控制面打印新指纹已下发，然后在 nic-1 **重新运行一次** iperf 命令。指纹识别主要发生在握手阶段，旧长连接不会因为改 JSON 自动生成新 SYN。

本版保留时间戳兼容性检查：当前 Linux 输入到部分不带 TS 的目标签名转换有已知校验和问题，因此不会把这些配置伪装成“已验证可用”。不要仅删除页面警告或绕过检查来增加可选数量。

如果直接使用 `test_p0f/test.py` 原控制面而非网页适配器，活动文件变为 `test_p0f/fps.json`，不产生 HTML 遥测。推荐统一使用 `scripts/control.sh p0f`。

## 7. 停止

等客户端结束；在 nic-2 两个终端分别 Ctrl+C 退出自己启动的 p0f、iperf 服务。Tofino 先停控制面再停数据面。网页采集器另有独立进程，操作方法见 [HTML](HTML.md)。
