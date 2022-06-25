#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
# Team: WgpSec
# Team Github : https://github.com/wgpsec
# Author : TeamsSix
# Author blog : https://www.teamssix.com

import re
import os
import sys
import time
import traceback
import pandas
import base64
import requests
import argparse
import subprocess

from pandas import DataFrame
from rich.progress import track
from rich.table import Table
from rich.console import Console
from configparser import ConfigParser
from whois import whois
from json import JSONDecodeError

# 导入自定义函数
from ti_api.Nsfocus import nsfocus
from ti_api.ThreatBook import threatbook
from common.random_ua import random_useragent
from common.req import req

console = Console()
requests.packages.urllib3.disable_warnings()


def init(config_path):
    """
    初始化函数
    :param config_path:     配置文件路径
    :return:                无
    """
    # 不存在配置文件
    if not os.path.exists(config_path):
        console.log('检测到您可能是第一次运行本程序，请根据程序提示输入您的 API 地址，\
                    如果没有直接回车即可，但在查询时将不会调用相关模块')
        threatbook_api_0 = input("请输入您的微步 Api: ")
        threatbook_api_1 = input("请再输入一个微步 Api，若无，则直接回车：")
        nsfocus_api = input('请输入您的绿盟 Api，若无，则直接回车：')
        fofa_email = input('请输入您的 Fofa 邮箱：')
        fofa_api = input('请输入您的 Fofa Api: ')
        # 该部分必须顶格
        config_text = f'''[Api Config]
ThreatBook_enable = True
Nsfocus_enable = False
FOFA_enable = True
# 逆向解析域名可获取更多域名相关信息，建议与 Fofa 开关配合使用
Revrse_IP_Lookup_enable = True

[ThreatBook]
# 微步威胁情报查询，查看 api 地址：https://x.threatbook.cn/v5/myApi（每天 50 次的免费额度）
# 支持写入多个，API 顺序读取，第一个查询达到上限 50 个时，则更换为下一个
api_key_0 = '{threatbook_api_0}'
api_key_1 = '{threatbook_api_1}'

[Nsfocus]
# 绿盟威胁情报查询，需要自行获取
Nsfocus_api = '{nsfocus_api}'

[FOFA]
# Fofa ip 信息查询，查看 api 地址：https://fofa.info/userInfo
#（付费，普通会员每次 100 条，高级会员每次 10000 条）
Fofa_email = '{fofa_email}'
Fofa_api = '{fofa_api}'
size = 100
'''
        with open(config_path, 'w', encoding='utf-8-sig') as w:
            w.write(config_text)
    else:
        with open(config_path, encoding='utf-8-sig') as f:
            f = f.read()
        if '[ThreatBook]' not in f:
            os.rename(config_path, config_path + '.bak')
            init(config_path)


def is_ip(ip):
    """
    判断 IP 是否合法
    :param ip:      IP 地址
    :return:        bool 类型
    """
    if re.match(r'^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.'
                r'(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.'
                r'(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.'
                r'(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$', ip):
        return True
    else:
        return False


def is_ip_alive_cmd(ip):
    """
    检测 ip 是否存活，通过 ping 命令的方式检测 IP 是否存活，可信度不高，因此后续的函数并未调用
    :param ip:     ip 地址
    :return:       存活返回 True，否则返回 False
    """
    # 判断 ip 是否存活
    try:
        os_name = os.name
        if os_name == 'nt':
            cmd = f"ping -n 1 {ip}"
        else:
            cmd = f"ping -c 1 {ip}"

        # 执行命令
        output = subprocess.check_output(cmd, shell=True).decode('utf-8')
        # 判断是否存活
        if 'unreachable' in output:
            return False
        else:
            return True
    except subprocess.CalledProcessError as exc:
        console.log(f"[red][EROR] 检测 {ip} ping 命令程序错误，cmd: {exc.cmd}; output: {exc.output}; [/red]")
        return False
    except Exception:
        console.log(f"[red][EROR] 检测 {ip} 是否存活发生程序错误，错误信息：{traceback.format_exc()}[/red]")
        return False


def reverse_ip_lookup(ip, proxies):
    """
    通过 IP 反查域名，返回域名
    https://api.hackertarget.com/reverseiplookup/?q=x.x.x.x     请求次数每日免费仅 10 次，因此删除该链接
    :param ip:     ip 地址
    :return:       域名列表，list 类型
    """
    domain_list = []
    url = f"http://api.webscan.cc/?action=query&ip={ip}"

    r = req(url, headers=random_useragent(), proxies=proxies)
    # 当且仅当 Response 对象存在且不为 'null' 时，才返回域名列表
    try:
        if r and r.text != 'null':
            domain_list = []
            for i in r.json():
                domain_list.append(i['domain'].strip())
            return domain_list
        else:
            return domain_list
    except JSONDecodeError:
        console.log(f"[red][EROR] 反查 {ip} 域名 json 解析错误，原始信息：{r.text}[/red]")
        return domain_list
    except Exception:
        console.log(f"[red][EROR] 反查 {ip} 域名发生程序错误，错误信息：{traceback.format_exc()}[/red]")
        return domain_list


def fofa(ip, fofa_email, fofa_api, size):
    """
    查询 fofa 接口
    :param ip:              查询 IP
    :param fofa_email:      fofa 账户，email 格式
    :param fofa_email:      fofa API
    :return:
        fofa_port:          fofa 开放端口，string 类型，以逗号分隔
        fofa_domain_list:   fofa 开放域名，list 类型
    """
    global fofa_port
    fofa_port = ""
    global fofa_domain_list
    fofa_domain_list = []
    if fofa_api == "":
        console.log('[red][EROR] 未检测到 Fofa API[/red]')
        return fofa_port, fofa_domain_list
    else:
        # fofa api 接口 URL
        url = f"https://fofa.info/api/v1/search/all"
        search_string_byte = base64.b64encode(ip.encode('utf-8')).decode()
        proxies = {'http': None, 'https': None}
        # 查询参数
        query = {
            "email": fofa_email,
            "key": fofa_api,
            "qbase64": search_string_byte,
            "size": size
        }
        # 查询
        r = req(url, random_useragent(), params=query, proxies=proxies)
        try:
            r_json = r.json()

            # 判断是否查询成功，成功返回 True，否则返回 False
            if not r_json['error']:
                """correct demo_data, size = 3:
                {
                    "error": false,
                    "mode": "extended",
                    "page": 1,
                    "query": "ip=\"1.1.1.1\"",
                    "results": [
                        [
                            "https://cdnwd.net",
                            "1.1.1.1",
                            "443"
                        ],
                        [
                            "cdnwd.net",
                            "1.1.1.1",
                            "80"
                        ],
                        [
                            "cdnwd.net:53",
                            "1.1.1.1",
                            "53"
                        ]
                    ],
                    "size": 23754
                }
                """
                # 获取 fofa 查询结果中的开放端口信息
                ip_port = [i[2] for i in r_json['results']]

                if ip_port:
                    # 去重
                    ip_port_list = list(set(ip_port))
                    # 排序
                    ip_port_list.sort(key=int)
                    # 转换成字符串
                    fofa_port = ",".join(ip_port_list)

                # 获取 fofa 查询结果中的开放域名信息
                for i in r_json['results']:
                    # url 为 result 中第一个元素，第二个元素为 ip，第三个元素为 port
                    url = i[0]
                    if ip not in url:
                        # 判断 url 是否包含 http:// 或 https://，如果包含，则以 "://" 为分隔符，取出 ip:port
                        if url.startswith('http') or url.startswith('https'):
                            url = url.split('://')[1]
                        # 去除 url 中端口号
                        url = url.split(':')[0]
                        # 确保筛选出的域名中不包含 IP 地址
                        if not is_ip(url):
                            fofa_domain_list.append(url.split(':')[0])
                    # 返回 fofa 查询结果中的开放域名信息（暂不去重，与其他 API 接口一起去重）及开放端口信息
                return (fofa_port, fofa_domain_list)
            elif r_json['error']:
                """incorrect demo_data:
                {
                    "errmsg": "[-700] Account Invalid",
                    "error": true
                }
                """
                # 700 为账号异常
                if "[-700]" in r_json['errmsg']:
                    console.log(f"[red][EROR] Fofa API 调用失败，错误原因：账号无效 [/red]")
                else:
                    console.log(f"[red][EROR] Fofa 获取数据发生错误，错误信息：{r_json['errmsg']}[/red]")
                return fofa_port, fofa_domain_list

            else:
                console.log(f"[red][EROR] 查询 {ip} 的 Fofa 信息发生错误，请求 {url} 返回错误信息：{r_json}[/red]")
                return fofa_port, fofa_domain_list
        except JSONDecodeError:
            console.log(f"[red][EROR] 查询 {ip} 的 Fofa 信息 json 解析错误，原始信息：{r.text}[/red]")
            return fofa_port, fofa_domain_list
        except Exception:
            console.log(f"[red][EROR] 查询 {ip} 的 Fofa 信息发生错误，错误信息：{traceback.format_exc()}[/red]")
            return fofa_port, fofa_domain_list


def domain_info_query(domain, proxies=None):
    """
    查询域名信息
    :param domain:      域名，string 类型
    :param proxies:     代理
    :return:
        domain_info:        正常解析的域名信息，dict 类型
        domain_json_error   json 格式解析异常的域名
        domain_error        请求错误或 whois 解析错误的域名
        domain_edu          edu 域名信息
    """
    global domain_info
    # 初始化域名信息
    domain_info = {
        '域名': domain,
        '标题': 'N/A',
        '备案类型': 'N/A',
        '备案名称': 'N/A',
        '备案号': 'N/A',
        '注册人': 'N/A',
        '注册邮箱': 'N/A',
        '注册商': 'N/A',
        '注册时间': 'N/A',
        '到期时间': 'N/A'
    }
    # json 解析错误的域名列表
    domain_json_error = []
    # 请求错误的域名列表
    domain_error = []
    # edu 域名列表
    domain_edu = []
    # 互联网信息服务（icp）备案信息查询

    # 域名备案信息查询 API
    icp_url = f"https://api.vvhan.com/api/icp?url={domain}"
    # 查询 ICP 域名备案信息
    icp_rep = req(icp_url, headers=random_useragent(), proxies=proxies)

    try:
        if icp_rep:
            """incorrect demo:
            {
                "message": "请输入正确的域名",
                "success": true
            }
            {
                "message": "参数输入不完整",
                "success": false
            }
            """
            icp_rep_json = icp_rep.json()
            # 接口调用成功，但参数异常
            if not icp_rep_json['success']:
                """incorrect demo:
                    {
                        "message": "请输入正确的域名",
                        "success": true
                    }
                    {
                        "message": "参数输入不完整",
                        "success": false
                    }
                    """
                # console.log(f"[red][EROR] 查询 {domain} 的 ICP 信息发生错误，错误信息：{icp_rep_json['message']}[/red]")
                domain_error.append(domain)
            # 接口调用成功，但未查询到数据
            elif 'message' in icp_rep_json:
                """incorrect demo:
                {
                    "message": "此域名未备案",
                    "success": true
                }
                """
                # 建议不打印 未查询到备案的信息，避免过多信息
                # console.log(f"[blue][INFO] 查询 {domain} 的 ICP 备案未查询到，错误信息：{icp_rep_json['message']}[/blue]")
                domain_error.append(domain)
            # 查询到备案信息
            elif 'info' in icp_rep_json:  # 存在备案信息
                """correct demo:
                {
                    "domain": "baidu.com",
                    "info": {
                        "icp": "京 ICP 证 030173 号 -1",
                        "name": "北京百度网讯科技有限公司",
                        "nature": "企业",
                        "time": "2022-06-19 23:13:26",
                        "title": "百度"
                    },
                    "success": true
                }
                """
                icp_info = icp_rep_json['info']
                domain_info['标题'] = icp_info['title']
                domain_info['备案类型'] = icp_info['nature']
                domain_info['备案名称'] = icp_info['name']
                domain_info['备案号'] = icp_info['icp']
            # 未知错误
            else:
                # console.log(f"[red][EROR] 查询 {domain} 的 ICP 信息发生错误，请求 {icp_url} 错误信息：{icp_rep_json}[/red]")
                domain_error.append(domain)
    except JSONDecodeError:
        # console.log(f"[red][EROR] 查询 {domain} 的备案信息 JSON 解析异常。[/red]")
        domain_json_error.append(domain)
    except Exception:
        # console.log(f"[red][EROR] 查询 {domain} 的备案信息发生程序错误 [/red]")
        domain_error.append(domain)

    # 根据域名查询 whois 注册信息
    try:
        # edu 域名不支持查询 whois 接口
        if "edu.cn" in domain:
            domain_edu.append(domain)
            return domain_info, domain_json_error, domain_error, domain_edu
        else:
            # 利用 python-whois 接口，查询 whois 域名注册信息，使用 flag 标志可以避免打印信息中断进度条打印
            # "Error trying to connect to socket: closing socket"
            # flags = 0
            # flags = flags | whois.NICClient.WHOIS_QUICK
            domain_whois = whois(domain)
            if domain_whois:
                domain_whois_dict = domain_whois
                """correct demo:
                {
                    "domain_name": [
                        "TAOBAO.COM",
                        "taobao.com"
                    ],
                    "registrar": "Alibaba Cloud Computing (Beijing) Co., Ltd.",
                    "whois_server": "grs-whois.hichina.com",
                    "referral_url": null,
                    "updated_date": "2022-05-18 16:35:45",
                    "creation_date": "2003-04-21 03:50:05",
                    "expiration_date": "2023-04-21 03:50:05",
                    "name_servers": [
                        "NS4.TAOBAO.COM",
                        "NS5.TAOBAO.COM",
                        "NS6.TAOBAO.COM",
                        "NS7.TAOBAO.COM"
                    ],
                    "status": [
                        "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
                        "serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited",
                        "serverTransferProhibited https://icann.org/epp#serverTransferProhibited",
                        "serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited"
                    ],
                    "emails": "DomainAbuse@service.aliyun.com",
                    "dnssec": "unsigned",
                    "name": null,
                    "org": null,
                    "address": null,
                    "city": null,
                    "state": "zhe jiang",
                    "zipcode": null,
                    "country": "CN"
                    }
                """

                """incorrect demo:
                {
                    "domain_name": null,
                    "registrar": null,
                    "creation_date": null,
                    "expiration_date": null,
                    "name_servers": null,
                    "status": null,
                    "emails": null,
                    "dnssec": null,
                    "name": null
                }
                """
                # 判断是否有注册人信息
                register_name = domain_whois_dict['name']
                domain_info['注册人'] = register_name if register_name else "N/A"

                # 判断是否有注册公司信息
                if 'org' in domain_whois_dict:
                    register_org = domain_whois_dict['org']
                    domain_info['注册商'] = register_org if register_org else "N/A"
                else:
                    domain_info['注册商'] = "N/A"

                register_mails = domain_whois_dict['emails']
                if register_mails is not None:
                    # 判断 注册邮箱返回值是否为列表，如果是列表，则转换为字符串，否则直接赋值
                    if isinstance(register_mails, list):
                        domain_info['注册邮箱'] = ",".join(register_mails)
                    else:
                        domain_info['注册邮箱'] = register_mails
                else:
                    domain_info['注册邮箱'] = "N/A"

                # 判断是否有注册时间信息
                register_time = domain_whois_dict['creation_date']
                domain_info['注册时间'] = register_time.strftime('%Y-%m-%d %H:%M:%S') if register_time else "N/A"

                # 判断是否有过期时间信息
                expire_time = domain_whois_dict['expiration_date']
                if expire_time is not None:
                    # 判断 过期时间返回值是否为列表，如果是列表，则转换为字符串，否则直接赋值
                    """demo:
                    "expiration_date": [
                        "2023-04-14 08:23:52",
                        "2024-04-14 08:23:52"
                      ]
                    """
                    if isinstance(expire_time, list):
                        for time_ in expire_time:
                            domain_info['到期时间'] = time_.strftime('%Y-%m-%d %H:%M:%S') + ","
                    else:
                        domain_info['到期时间'] = expire_time.strftime('%Y-%m-%d %H:%M:%S')

                return domain_info, domain_json_error, domain_error, domain_edu
            else:
                # console.log(f"[red][EROR] 查询 {domain} 的 whois 注册信息发生错误，返回信息：{domain_whois}[/red]")
                domain_error.append(domain)
                return domain_info, domain_json_error, domain_error, domain_edu
    except Exception:
        # console.log(f"[red][EROR] 查询 {domain} 的 Whois 信息发生程序错误，错误信息:{traceback.format_exc()}[/red]")
        domain_error.append(domain)
        return domain_info, domain_json_error, domain_error, domain_edu


def main(ip, config_path, proxies):
    """
    主函数，根据配置文件中的使能开关，执行不同的查询 API 函数
    :param ip:              查询 IP
    :param config_path:     配置文件路径
    :param proxies:         代理
    :return:                
        threatbook_data         dict 类型，微步数据，用于后续写入 EXCEL 保存数据
        nsfocus_data            dict 类型，绿盟数据，用于后续写入 EXCEL 保存数据
        domain_info_data = {}   dict 类型，域名信息，用于后续写入 EXCEL 保存数据
    """
    # 用于保存 EXCEL 数据

    threatbook_data = {}
    nsfocus_data = {}
    domain_info_data = {}
    # 初始化 ConfigParser 对象，读取配置文件
    # global cfg
    cfg = ConfigParser()
    cfg.read(config_path, encoding='utf-8-sig')

    # 设置全局参数
    # fofa 查询域名列表
    global fofa_domain_list
    fofa_domain_list = {}

    # 读取微步情报查询使能开关
    threabook_enable = cfg.get('Api Config', 'ThreatBook_enable').strip("'")
    # 读取绿盟情报查询使能开关
    nsfocus_enable = cfg.get('Api Config', 'Nsfocus_enable').strip("'")

    # 判断是否查询威胁情报，若无则不打印表格
    if threabook_enable or nsfocus_enable:
        # 初始化表格，设置表格标题
        table = Table(show_lines=True)
        table.add_column('情报来源', justify="center")
        table.add_column('是否为恶意 IP', justify="center")
        table.add_column('危害程度', justify="center")
        table.add_column('威胁类型', justify="center")
        table.add_column('标签', justify="center")
        table.add_column('标签类型', justify="center")
        table.add_column('场景', justify="center")
        table.add_column('IP 基本信息', justify="center")
        table.add_column('IP 地理位置', justify="center")
        table.add_column('情报可信度', justify="center")

        # 判断是否查询微步情报
        if threabook_enable == "True":
            # 获取微步 API_KEY 密钥列表
            threatbook_api_key_chain = {k: v for k, v in cfg.items('ThreatBook')}.values()
            # 获取微步情报数据
            table, threatbook_result = threatbook(ip, threatbook_api_key_chain, table)

            # EXCEL 表格数据
            threatbook_data['来源'] = threatbook_result[9]
            threatbook_data['ip'] = ip
            threatbook_data['是否为恶意 IP'] = threatbook_result[0]
            threatbook_data['危害程度'] = threatbook_result[1]
            threatbook_data['威胁类型'] = threatbook_result[2]
            threatbook_data['标签'] = threatbook_result[3]
            threatbook_data['标签类型'] = threatbook_result[4]
            threatbook_data['场景'] = threatbook_result[5]
            threatbook_data['IP 基本信息'] = threatbook_result[6]
            threatbook_data['IP 地理位置'] = threatbook_result[7]
            threatbook_data['情报可信度'] = threatbook_result[8]

        # 判断是否查询绿盟情报
        if nsfocus_enable == "True":
            # 获取微步 API_KEY 密钥列表
            nsfocus_api_key = cfg.get('Nsfocus', 'Nsfocus_api').strip("'").strip()
            # 获取绿盟情报数据
            table, nsfocus_result = nsfocus(ip, nsfocus_api_key, table)

            # EXCEL 表格数据
            nsfocus_data['来源'] = nsfocus_result[9]
            nsfocus_data['ip'] = ip
            nsfocus_data['是否为恶意 IP'] = nsfocus_result[0]
            nsfocus_data['危害程度'] = nsfocus_result[1]
            nsfocus_data['威胁类型'] = nsfocus_result[2]
            nsfocus_data['标签'] = nsfocus_result[3]
            nsfocus_data['标签类型'] = nsfocus_result[4]
            nsfocus_data['场景'] = nsfocus_result[5]
            nsfocus_data['IP 基本信息'] = nsfocus_result[6]
            nsfocus_data['IP 地理位置'] = nsfocus_result[7]
            nsfocus_data['情报可信度'] = nsfocus_result[8]
        # 打印表格
        console.print(table)

    # 读取 FOFA 情报查询使能开关
    fofa_enable = cfg.get('Api Config', 'FOFA_enable').strip("'")
    # 判断是否查询 FOFA 开放端口，若无则不打印表格
    if fofa_enable == "True":
        # 获取 FOFA 账号及 API
        fofa_email = cfg.get('FOFA', 'Fofa_email').strip("'")
        fofa_api = cfg.get('FOFA', 'Fofa_api').strip("'").strip()
        fofa_size = cfg.get('FOFA', 'size').strip("'").strip()
        # 获取 fofa 情报数据
        fofa_port, fofa_domain_list = fofa(ip, fofa_email, fofa_api, fofa_size)

        # 判断 fofa 查询 fofa 端口信息，如果为 空 则无需格式化 table 输出
        if fofa_port:
            # 打印 IP 开放端口信息
            console.log(f"[green][SUCC] {ip} 开放端口信息，来源于 Fofa: [/green]")
            table = Table(show_lines=True)
            table.add_column(' IP 可能开放端口', justify="center")
            table.add_row(fofa_port)
            console.print(table)
            time.sleep(1)
        else:
            console.log(f"[yellow][INFO] {ip} 开放端口信息信息未查询到，来源于 Fofa: [/yellow]")

        # EXCEL 表格数据，确认功能是否开启。
        if threabook_enable == "True":
            threatbook_data['IP 可能开放端口'] = fofa_port
        if nsfocus_enable == "True":
            nsfocus_data['IP 可能开放端口'] = fofa_port

    # 读取逆向解析域名使能开关
    reverse_enable = cfg.get('Api Config', 'Revrse_IP_Lookup_enable').strip("'")
    # 判断是否逆向解析域名，若无则不打印表格
    if reverse_enable == "True":
        if fofa_enable != "True":
            console.log(f"[yellow][INFO] 逆向解析域名，建议同时打开 Fofa 使能开关，来查询更多域名相关信息！[/yellow]")
            # 通过 api.webscan.cc. 获取逆向解析域名数据，函数返回值为 list 类型
            ip_reverse_domain = reverse_ip_lookup(ip, proxies=proxies)

        else:
            # 通过 api.webscan.cc. 获取逆向解析域名数据，函数返回值为 list 类型
            ip_reverse_domain = reverse_ip_lookup(ip, proxies=proxies)
            # 通过 fofa 获取域名相关信息，函数返回值为 list 类型
            if fofa_domain_list:
                # 将 fofa 查询结果 list 类型转为 set 集合去重，合并至 ip_reverse_domain 中
                ip_reverse_domain.extend(set(fofa_domain_list))
        # 确保解析域名列表 不为空，否则将无法获取更多域名信息
        if ip_reverse_domain:
            # 数据过滤，去除 ip，去重
            for i in ip_reverse_domain:
                if is_ip(i):
                    ip_reverse_domain.remove(i)
            ip_reverse_domain = list(set(ip_reverse_domain))
            # 排序，随意，只是 domain 输出排序好看
            ip_reverse_domain.sort()

        else:
            # 未逆向解析到域名列表
            console.log(f"[yellow][INFO] 未查询到 {ip} 的反查域名 [/yellow]")
            return threatbook_data, nsfocus_data, domain_info_data
        console.log(f"[yellow][INFO] {ip} 反查到 {len(ip_reverse_domain)} 个 域名，正在查询域名相关信息，请稍等……[/yellow]")

        # 创建域名信息表格
        table = Table(show_lines=True)
        table.add_column('域名', justify="center")
        table.add_column('标题', justify="center")
        table.add_column('备案类型', justify="center")
        table.add_column('备案名称', justify="center")
        table.add_column('备案号', justify="center")
        table.add_column('注册人', justify="center")
        table.add_column('注册邮箱', justify="center")
        table.add_column('注册商', justify="center")
        table.add_column('注册时间', justify="center")
        table.add_column('到期时间', justify="center")
        # 表格样式初始化
        domain_info_data['ip'] = []
        domain_info_data['域名'] = []
        domain_info_data['标题'] = []
        domain_info_data['备案类型'] = []
        domain_info_data['备案名称'] = []
        domain_info_data['备案号'] = []
        domain_info_data['注册人'] = []
        domain_info_data['注册邮箱'] = []
        domain_info_data['注册商'] = []
        domain_info_data['注册商'] = []
        domain_info_data['注册时间'] = []
        domain_info_data['到期时间'] = []
        # json 解析异常的域名
        domain_json_error_list = []
        # edu 的域名无法获取
        domain_edu_list = []
        # 未备案，程序错误，请求错误的域名
        domain_error_list = []
        try:
            # 该函数仅用于下列判断循环调用
            def query():
                # 避免异常信息打印打断 进度条，因此将所有 console.log 注释掉，后续调试可以打开
                domain_info_dict, domain_json_error_list, domain_error_list, domain_edu_list = domain_info_query(
                    domain=domain.strip(),
                    proxies=proxies)
                # 将每次查询的结果添加至域名信息中
                table.add_row(*(domain_info_dict.values()))
                # 添加至表格中，类似于 data = {"name":["lily","ailcie"],"cost":[100,20]} 的样式
                # 因此循环将 domain_info_dict 中的数据，添加进 domain_info_data 字典中
                # 考虑到一个 IP 可能返回多个域名解析结果，因此需要将 域名信息 单独写入第二个 sheet
                for i in domain_info_data.keys():
                    if i == "ip":
                        domain_info_data['ip'].append(ip)
                    else:
                        domain_info_data[i].append(domain_info_dict[i])
            # 实际测试，域名个数大于 3 个，耗时较久，为了更好的交互体验，添加进度条
            if len(ip_reverse_domain) > 3:
                for domain in track(ip_reverse_domain, description='域名信息查询进度：'):
                    query()
            else:
                # 同上，只是个数不超过 3 个时，无需进度条，可直接显示
                for domain in ip_reverse_domain:
                    query()
            if domain_json_error_list:
                console.log("[red][EROR] 以下域名的查询备案信息 JSON 解析异常。[/red]")
                console.log(domain_json_error_list)
            if domain_edu_list:
                console.log(f"[yellow][INFO] 以下 edu 域名的 whois 注册信息请求错误，暂不支持中国教育域名查询 [/yellow]")
                console.log(domain_edu_list)
            if domain_error_list:
                console.log("[red][EROR] 以下域名的请求 ICP 或 whois 信息异常。[/red]")
                console.log(domain_error_list)
        except Exception:
            console.log(f"[red][EROR] 当前域名：{domain} 的信息查询存在异常，打印信息如下 [/red]")
            console.log(traceback.format_exc())
        # 打印表格
        console.log(f"[green][SUCC] {ip} 域名反查信息：[/green]")
        if domain_info_data:
            console.print(table)

    # 返回最终数据，用于写入 EXCEL 中
    return threatbook_data, nsfocus_data, domain_info_data


if __name__ == '__main__':
    console.print('''[bold blue]
+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
|T|h|r|e|a|t| |I|n|t|e|l|l|i|g|e|n|c|e| |G|a|t|h|e|r|i|n|g|
+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
    团队：狼组安全团队   作者：TeamsSix    版本：0.5.5       
    ''')
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', dest='config', help='指定配置文件，默认 ./config.ini')
    parser.add_argument('-f', dest='file', help='指定 IP 文本，一行一个')
    parser.add_argument('-i', dest='ip', help='指定目标 IP')
    parser.add_argument('-p', dest='proxy', help='指定代理，比如：http://127.0.0.1:1080 或者 socks5://127.0.0.1:1080')
    parser.add_argument('-o', dest='output', help='导出为 excel 表格，例如 output.xlsx')
    args = parser.parse_args()

    # ip 计数
    count = 1
    # 全局变量，存放需要运行的代码的绝对路径
    root_path = sys.path[0]
    threatbook_result = {}
    nsfocus_result = {}
    domain_info_result = {}

    # 配置文件路径参数
    if args.config:
        config_path = args.config
        if not os.path.exists(config_path):
            console.log('[red][EROR] 未找到配置文件，请确认配置文件路径是否正确 [/red]')
            sys.exit()
    else:
        config_path = f"{root_path}/config.ini"
        init(config_path)

    # 代理参数
    if args.proxy:
        proxies = {'http': args.proxy, 'https': args.proxy}
    else:
        proxies = {'http': None, 'https': None}

    # 用于保存 excel 数据
    pools = []

    # 保存至 excel 中
    def write_file_to_output(threatbook_result, nsfocus_result, domain_info_result):
        # 初始化，用于控制后续写几张 sheet 表
        ti_columns = []
        domain_colums = []
        # 判断最极端情况，所有数据均为空
        if not threatbook_result and not nsfocus_result and not domain_info_result:
            console.log(f"[red][EROR] 无任何数据需要保存，请确认查询结果！[/red]")
        # 获取威胁情报 列名
        elif threatbook_result and nsfocus_result:
            ti_columns = threatbook_result.keys()
        elif threatbook_result:
            ti_columns = threatbook_result.keys()
        elif nsfocus_result:
            ti_columns = nsfocus_result.keys()

        # 获取域名信息列名
        if domain_info_result:
            domain_colums = domain_info_result.keys()

        # 保存文件名
        if args.output:
            output_filename = args.output
            if ".xlsx" not in output_filename:
                output_filename = f"{output_filename}.xlsx"
            if os.path.exists(output_filename):
                console.log(f"[red][EROR] {output_filename} 文件已存在 [/red]")
                sys.exit()
        else:

            if not os.path.exists(f"{root_path}/output"):
                os.mkdir(f"{root_path}/output")
            current_time = time.strftime("%Y年%m月%d日_%H时%M分%S秒")
            filename_suffix = f"_{count}个 IP.xlsx"
            output_filename = f"{root_path}/output/tig_{current_time}{filename_suffix}"

        try:
            # 威胁情报数据转换成 excel DataFrame 数据
            ti_df = DataFrame(pools, columns=ti_columns)
            # 域名信息转换成 excel DataFrame 数据
            domain_df = DataFrame(domain_info_result, columns=domain_colums)
            # 以下方法可实现将两份数据分别写入不同的 sheet 中，否则会被覆盖
            with pandas.ExcelWriter(output_filename) as writer:
                if ti_columns:
                    ti_df.to_excel(writer, sheet_name='威胁情报')
                if domain_colums:
                    domain_df.to_excel(writer, sheet_name='域名信息')

            time.sleep(1)
            console.log(f"[green][SUCC] 结果已保存至 {output_filename}[/green]")
        except Exception:
            console.log(f"[red][EROR] 保存数据发生程序错误，错误信息：{traceback.format_exc()}[/red]")

    # 在实际使用中发现，单一 IP 需要保存信息的情况并不多，因此，设置 output 与 ip 参数同时设置时才保存结果
    if args.ip and args.output:
        ip = args.ip
        console.rule(f"[yellow] 正在查询 {ip} 的情报信息 [/yellow]", style="yellow")
        threatbook_result, nsfocus_result, domain_info_result = main(ip, config_path, proxies)
        if threatbook_result:
            pools.append(threatbook_result)
        if nsfocus_result:
            pools.append(nsfocus_result)
        write_file_to_output(threatbook_result, nsfocus_result, domain_info_result)

    # 否则，单一 IP 时，不保存结果，仅打印信息
    elif args.ip:
        ip = args.ip
        console.rule(f"[yellow] 正在查询 {ip} 的情报信息 [/yellow]", style="yellow")
        main(ip, config_path, proxies)
        # threatbook_result, nsfocus_result, domain_info_result = main(ip, config_path, proxies)

    # ip 文件列表
    elif args.file:
        with open(args.file) as f:
            # content_list ip 字符串不携带空格
            content_list = f.readlines()
        # 文件对象转化为字符串，并从字符串中将 IP 正则匹配出来
        ip_list = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', "".join(content_list))

        count = len(ip_list)
        for index, ip in enumerate(ip_list):
            console.rule(f"[yellow][INFO] 正在查询 {ip} 的情报信息，剩余 {count - index} 个 IP[/yellow]", style="yellow")
            threatbook_result, nsfocus_result, domain_info_result = main(ip, config_path, proxies)
            if threatbook_result:
                pools.append(threatbook_result)
            if nsfocus_result:
                pools.append(nsfocus_result)
        write_file_to_output(threatbook_result, nsfocus_result, domain_info_result)
    else:
        console.log('[yellow][INFO] 请输入待扫描的 IP 或 IP 列表文件 [/yellow]')
        sys.exit()
