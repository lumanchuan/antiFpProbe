# HTML 网页部署与运行

[English](HTML_EN.md) | 简体中文

网页代码全部位于 `HTML/`；页面分为科技风入口、Nmap 工作台和 p0f 工作台。后端运行在 **Tofino1**，p0f 观测采集器运行在 **nic-2**。网页不需要安装在两台 NIC 上。

## 1. 安装独立网页环境

在 Tofino 项目根目录，选择已有的 Python 3.9 或更高版本。下面 `python3.9` 可换成本机该解释器的绝对路径，但不能把系统/SDE 的 Python 3.5 升级覆盖。

```bash
python3.9 -m venv .venv
.venv/bin/python -m pip install -r HTML/requirements.txt
```

如交换机不能访问软件源，可在相同 OS、CPU 架构和 Python ABI 的联网机器准备 wheel：

```bash
python3.9 -m pip download -r HTML/requirements.txt -d wheels
```

安全传输到设备后用 `pip install --no-index --find-links /path/to/wheels -r HTML/requirements.txt`。第三方安装包需遵守各自许可证，不要通过关闭 TLS 校验绕过证书错误。

## 2. 配置与启动

先按 [部署文档](部署.md) 完成初始化和三模式编译。以下是原实验台管理地址的示例，可替换。

```bash
export SDE=/root/bf-sde-9.7.0
/usr/bin/python3 scripts/configure.py --sde "$SDE" \
  --web-host 0.0.0.0 --web-port 5080 \
  --switch-address 192.168.30.252 --sensor-address 192.168.30.131
.venv/bin/python scripts/web_service.py start
.venv/bin/python scripts/web_service.py status
```

浏览器打开 `http://192.168.30.252:5080`。第一次启动自动生成全新的管理令牌，在 Tofino 终端读取：

```bash
cat HTML/runtime/admin.token
```

将令牌填到登录框。不要把令牌提交到 Git、公开截图、说明书或在线笔记。不要使用之前部署的旧访问码。`HTML/runtime` 目录是私有运行数据。

日志：

```bash
tail -n 80 HTML/runtime/web.log
tail -n 80 HTML/runtime/data.log
tail -n 80 HTML/runtime/control.log
```

启动脚本不会终止已占用 5080 的其他服务。若端口被占用，先确认是谁在用；可把 `--web-port` 改为其它端口，同时传入 `--switch-address` 更新采集回传 URL。

前台调试可以运行 `bash HTML/run_dashboard.sh`，Ctrl+C 只退出网页。后台管理脚本只认自己记录且 PID/启动时间匹配的网页进程。

## 3. Nmap 工作台

1. 从首页进入 Nmap。
2. 选择“监测转发”或“抗测绘”，点击启动。
3. 对话框列出当前数据面/控制面的程序名、PID、命令。确认才停止这些进程；取消则不启动。共享交换机上须先征得其他实验使用者同意。
4. 后端先检查构建文件，再按数据面 → 设备/BFRT 就绪 → 控制面 → 端口稳定的顺序启动。
5. nic-1 执行 [Nmap 文档](Nmap.md) 中的扫描，观察计数和会话。计数是当前检测规则匹配与会话估计，并非网络中一切扫描行为的完美统计。
6. 指纹库更换 JSON 后显示待下发/实际下发状态，不能只看选中标签判断已生效。

## 4. p0f 工作台与采集器

先从首页进入 p0f，登录。开启网页不会自动在 nic-2 抓包，也不会修改两台主机的 SSH 授权。

采集器使用本次网页生成的独立令牌，通过已有 SSH 安全通道在 nic-2 内存运行。可在同时具有两台 SSH 访问权限的终端执行下列命令。把 `RELEASE_DIR` 换成 Tofino 上这个包的**实际绝对路径**；这只是本次命令参数，源码无需改名。

```bash
RELEASE_DIR=/absolute/path/to/OSDisguise
ssh -o BatchMode=yes P4 "/usr/bin/python3 '$RELEASE_DIR/HTML/tools/sensor_bundle.py'" \
  | ssh -o BatchMode=yes nic-2 'python3 - --background'
```

Windows PowerShell 对应写法：

```powershell
$ReleaseDir = '/absolute/path/to/OSDisguise'
ssh -o BatchMode=yes P4 "/usr/bin/python3 '$ReleaseDir/HTML/tools/sensor_bundle.py'" | ssh -o BatchMode=yes nic-2 "python3 - --background"
```

两台 SSH 别名需由你事先配置；也可以换成实际 `user@host`。不需要从 Tofino 向 nic-2 增加新密钥。不要把管道输出保存到文件，因为其中含本次采集令牌。若出现 SSH 主机指纹错误，应核实服务器身份，不要关闭主机密钥校验。

采集器依赖 nic-2 上的 `/usr/sbin/p0f`、`/usr/bin/stdbuf`、`/sbin/ip` 和 `enp5s0f1`。输出 `OSDisguise p0f sensor PID ...` 后可在网页观察心跳。重复启动会被拒绝；它不会接管或杀掉已有 p0f 监听进程。

选择监测转发或 p0f 抗测绘模式，再按 [p0f 文档](p0f.md) 运行 iperf2。网页显示 `.3.1 → .3.2` 的客户端握手观测、签名和对比结果。若同时需要命令行 p0f 观察，独立终端也可以监听，两者互不接管。

停止采集器时在 nic-2 对**刚才输出并核实的 PID**发送 TERM：

```bash
ps -p <SENSOR_PID> -o pid,args
kill -TERM <SENSOR_PID>
```

采集器退出时只回收自己创建的 p0f 子进程。网页停止后采集器短暂重试，持续失联后暂停捕获并最终退出；正式结束演示仍应显式停止。

## 5. Nmap 与 p0f 切换

两个模式共用 ASIC，只能一个运行。所有切换都走同一进程确认机制；不需要重复编译。两种活动指纹分目录保存，p0f 会话带运行周期标识，避免把 Nmap 阶段旧观测算到新 p0f 阶段。

## 6. 停止网页服务

如需停止整个演示，先在页面点击停止按钮并确认数据面/控制面退出，然后停止 nic-2 采集器、自己的 iperf/临时 HTTP 服务。最后在 Tofino 项目根目录执行：

```bash
.venv/bin/python scripts/web_service.py stop
.venv/bin/python scripts/web_service.py status
```

**只停止网页不会停止交换机转发或抗测绘程序。** 不使用 `pkill python` 或按端口盲目杀进程。配置修改后通过上述管理脚本重启网页即可，是否停止 ASIC 由你另行明确操作。

## 7. 安全与显示配置

管理令牌在 `HTML/runtime/admin.token`，采集令牌在 `HTML/runtime/p0f-sensor.token`，两者不能互用。会话认证、CSRF 校验及采集来源限制保留。Flask 内置服务器用于可信内网演示，不是互联网生产部署方案。

`config/deployment.json` 的 `asset_label` 默认是用户指定的 `Linux 2.6`。实机内核默认“未核验”；你通过 `uname -r` 确认后可以增加 `verified_kernel` 和 `verified_at` 字段。它是人工核验记录，不是网页实时识别出的操作系统。
