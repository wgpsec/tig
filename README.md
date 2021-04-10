<h1 align="center">TIG  威胁情报收集 🪓</h1>

[![GitHub stars](https://img.shields.io/github/stars/wgpsec/tig)](https://github.com/wgpsec/tig) [![GitHub issues](https://img.shields.io/github/issues/wgpsec/tig)](https://github.com/wgpsec/tig/issues) [![GitHub release](https://img.shields.io/github/release/wgpsec/tig)](https://github.com/wgpsec/tig/releases)

# 0x00 介绍

tig `Threat Intelligence Gathering` 威胁情报收集，旨在提高蓝队拿到攻击 IP 后对其进行威胁情报信息收集的效率，目前已集成微步、IP 域名反查、Fofa 信息收集、ICP 备案查询、IP 存活检测、Whois 信息查询六个模块，现已支持以下信息的查询：

* ✅ 微步标签
* ✅ IP 域名反查
* ✅ IP 存活检测
* ✅ ICP 备案查询
* ✅ 开放端口查询
* ✅ Whois 信息查询
* ✅ IP 地理位置查询
*  ……

后续将集成更多模块，如有好的建议或遇到 Bug，欢迎提 issue

# 0x01 安装

需要 python3 环境支持

```
git clone https://github.com/wgpsec/tig.git
cd  tig
pip3 install -r requirements.txt
python3 tig.py
```

# 0x02 使用

工具命令如下：

```
-h, --help  查看帮助信息
-c CONFIG   指定配置文件，默认 ./config.ini
-f FILE     IP 文本，一行一个
-i IP       目标 IP
-p PROXY    指定代理，比如：http://127.0.0.1:1080 或者 socks5://127.0.0.1:1080
```

在开始使用工具之前，需要对配置文件进行配置，运行一下程序会自动生成配置文件，默认配置文件如下：

```
[Threat Intelligence]

# 微步威胁情报查询，查看 api 地址：https://x.threatbook.cn/nodev4/vb4/myAPI（每天 50 次的免费额度）
ThreatBook_enable = true
ThreatBook_api = ''

[IP Passive Information]

# IP 反查，调用 http://api.hackertarget.com/reverseiplookup/ 和 http://api.webscan.cc/ 的 api 接口
IP_reverse_enable = true

# ICP 备案信息查询，调用 https://api.vvhan.com/api/icp 的 api，如果目标 IP 没有反查到域名，该项即使开启也不会有输出
ICP_beian_enable = true

# Whois 信息查询，调用 https://api.devopsclub.cn/api/whoisquery 的 api
Whois_enable = true

# Fofa ip 信息查询，查看 api 地址：https://fofa.so/personalData（付费，普通会员每次100条，高级会员每次10000条）
Fofa_enable = true
Fofa_email = ''
Fofa_api = ''

[IP Active Information]

# 利用 ping 命令对 IP 进行存活检测
IP_survive_enable = true
```

在配置文件里添加自己的微步 API 和 Fofa API 才可使用相关模块，添加 API 后，就可以正常使用相关模块了。

例如这里获取某个 IP 的信息，直接使用 -i 命令即可。

![](https://teamssix.oss-cn-hangzhou.aliyuncs.com/Snipaste_2021-03-16_16-16-36.png)

# 0x03 最后

如果在工具使用的过程中发现存在 bug 等问题，欢迎提 issue

[![Stargazers over time](https://starchart.cc/wgpsec/tig.svg)](https://starchart.cc/wgpsec/tig)

