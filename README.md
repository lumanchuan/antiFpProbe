# OSDisguise：可编程交换机操作系统指纹防御实验系统

[English](README_EN.md) | 简体中文

基于 **Tofino1 硬件交换机 / Barefoot SDE 9.7.0 / P4_16**，对 Nmap 主动探测响应和 p0f 被动观察的 TCP 指纹进行处理，配套中文网页管理、指纹选择和监测展示。

这是竞赛复现与源码交付目录。可以整体改名或移动；源码不依赖原工程的安装路径。首次部署必须准备相应硬件、合法获得并安装的 SDE 和 Python 依赖，不能在普通电脑上直接运行 Tofino 数据面。

## 从哪里开始

1. [部署与环境检查](docs/部署.md)：三台机器、连线、软件环境、初始化、编译和自检。
2. [Nmap 操作步骤](docs/Nmap.md)：转发基线、主动指纹对抗、扫描及更换指纹。
3. [p0f 操作步骤](docs/p0f.md)：被动指纹对抗、监听、iperf2 通信及验收。
4. [HTML 操作步骤](docs/HTML.md)：安装网页环境、启动/停止服务、模式切换、采集器连接。
5. [架构、限制与排障](docs/架构与排障.md)：就绪与联通的区别、DPDK、Python ABI、识别边界。
6. [发布说明与来源](docs/发布说明.md)：Apache-2.0 适用范围、第三方声明、脱敏导出。
7. [验证记录](docs/验证记录.md)：本次实际验证范围和结果。

## 目录

```text
.
├── README.md / LICENSE / NOTICE / .gitignore
├── antiFpProbe.p4                 # Nmap/p0f 编译开关入口
├── nmap_tofino.p4                 # Nmap 数据面
├── p0f_tofino.p4                  # p0f 数据面
├── common/                       # 公共头文件，保留原声明
├── configs/                      # 示例业务转发表和 ARP 表
├── config/deployment.example.json# 部署配置示例
├── test_nmap/                    # Nmap 原控制面与初始指纹
├── test_p0f/                     # p0f 原控制面、规范化与示例指纹
├── monitor/scan_monitor/         # 独立监测转发数据面与控制面
├── HTML/                        # 网页、控制面适配器、采集器、指纹库
├── scripts/                     # 配置、构建、自检、启动、源码导出
├── tests/                       # Nmap 单元测试
└── docs/                        # 中英文部署、实验与发布文档
```

`build/`、`HTML/runtime/`、`.venv/`、`config/deployment.json` 是部署后生成的本地内容，不属于公开源码。首次收到的目录不携带旧令牌、数据库、日志、抓包或 SSH 密钥。

## 快速路径

以下在 **Tofino1 的项目根目录**执行。`SDE` 指向本机已安装 SDK；不要把示例地址当作自动安装命令。

```bash
export SDE=/root/bf-sde-9.7.0
python3 scripts/configure.py --sde "$SDE"

# PLATFORM_CONFIG 必须是本台交换机已验证可用的硬件配置文件。
export PLATFORM_CONFIG="$SDE/install/share/p4/targets/tofino/antiFpProbe.conf"
/usr/bin/python3 scripts/build.py all --platform-config "$PLATFORM_CONFIG"
/usr/bin/python3 scripts/doctor.py
```

上面的 `PLATFORM_CONFIG` 是现有实验台的例子。新机器没有该文件时，选择**本机 SDE 中已经能正常驱动该交换机的程序配置**，不要求该程序名为 antiFpProbe。构建器仅读取其硬件信息，不复制其旧 P4 程序，也不覆盖 SDK 安装目录。

手动运行：打开两个 Tofino 终端，在各自的项目根目录运行：

```bash
# 终端 1：选择 monitor、nmap 或 p0f
bash scripts/data.sh nmap
```

```bash
# 终端 2：等待终端 1 完成初始化，再运行同一模式
bash scripts/control.sh nmap
```

网页运行请看 [HTML.md](docs/HTML.md)。网页首次启动不会自动加载交换机程序；每次切换均需确认当前进程列表。

## 实验边界

- 默认业务链路：nic-1 `192.168.3.1` → Tofino → nic-2 `192.168.3.2`。
- Nmap 在 nic-1 扫描 nic-2；p0f 在 nic-2 观察 nic-1 发出的 TCP SYN。两者观察对象不同。
- 三个模式共享一台 ASIC，需要串行切换，不能同时加载。Nmap 与 p0f 分别编译并缓存，切换指纹无需重新编译。
- 指纹目录包含已有样例和候选记录。格式校验通过不等于所有版本均已通过硬件端到端测试；页面保留实际兼容性限制。
- 仅在自己拥有或已获授权的测试网络运行扫描、抓包与流量实验。

## 许可

作者拥有版权的代码及本次新增部署脚本、文档采用 **Apache License 2.0**，详见 [LICENSE](LICENSE)。第三方文件不自动改为 Apache-2.0，见 [NOTICE](NOTICE) 和 [发布说明](docs/发布说明.md)。目前尚有公共辅助头文件及指纹数据的来源/授权需发布者确认，不能把此目录直接宣称为“全部文件均已完成开源授权审核”。
