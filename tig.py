#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
# Team: WgpSec
# Team Github : https://github.com/wgpsec
# Author : TeamsSix
# Author blog : https://www.teamssix.com


import os
import sys
import time
import base64
import random
import requests
import argparse
import subprocess
from pandas import DataFrame
from rich.table import Table
from rich.progress import track
from rich.console import Console
from configparser import ConfigParser
from prettytable import PrettyTable

console = Console()
requests.packages.urllib3.disable_warnings()


def random_useragent():
    ua = [
        "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
        "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729; InfoPath.3; rv:11.0) like Gecko",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
        "Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
        "Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; en) Presto/2.8.131 Version/11.11",
        "Opera/9.80 (Windows NT 6.1; U; en) Presto/2.8.131 Version/11.11",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Maxthon 2.0)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; TencentTraveler 4.0)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; The World)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SE 2.X MetaSr 1.0; SE 2.X MetaSr 1.0; .NET CLR 2.0.50727; SE 2.X MetaSr 1.0)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Avant Browser)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)",
        "Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_3_3 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8J2 Safari/6533.18.5",
        "Mozilla/5.0 (iPod; U; CPU iPhone OS 4_3_3 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8J2 Safari/6533.18.5",
        "Mozilla/5.0 (iPad; U; CPU OS 4_3_3 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8J2 Safari/6533.18.5",
        "Mozilla/5.0 (Linux; U; Android 2.3.7; en-us; Nexus One Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1",
        "MQQBrowser/26 Mozilla/5.0 (Linux; U; Android 2.3.7; zh-cn; MB200 Build/GRJ22; CyanogenMod-7) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1",
        "Opera/9.80 (Android 2.3.4; Linux; Opera Mobi/build-1107180945; U; en-GB) Presto/2.8.149 Version/11.10",
        "Mozilla/5.0 (Linux; U; Android 3.0; en-us; Xoom Build/HRI39) AppleWebKit/534.13 (KHTML, like Gecko) Version/4.0 Safari/534.13",
        "Mozilla/5.0 (BlackBerry; U; BlackBerry 9800; en) AppleWebKit/534.1+ (KHTML, like Gecko) Version/6.0.0.337 Mobile Safari/534.1+",
        "Mozilla/5.0 (hp-tablet; Linux; hpwOS/3.0.0; U; en-US) AppleWebKit/534.6 (KHTML, like Gecko) wOSBrowser/233.70 Safari/534.6 TouchPad/1.0",
        "Mozilla/5.0 (SymbianOS/9.4; Series60/5.0 NokiaN97-1/20.0.019; Profile/MIDP-2.1 Configuration/CLDC-1.1) AppleWebKit/525 (KHTML, like Gecko) BrowserNG/7.1.18124",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0; HTC; Titan)",
        "UCWEB7.0.2.37/28/999",
        "NOKIA5700/ UCWEB7.0.2.37/28/999",
        "Openwave/ UCWEB7.0.2.37/28/999",
        "Mozilla/4.0 (compatible; MSIE 6.0; ) Opera/UCWEB7.0.2.37/28/999",
        "Mozilla/6.0 (iPhone; CPU iPhone OS 8_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/8.0 Mobile/10A5376e Safari/8536.25"]
    random_user_agent = {"User-Agent": random.choice(ua)}
    return random_user_agent


def init(config_path):
    if not os.path.exists(config_path):  # 不存在配置文件
        console.log('检测到您可能是第一次运行本程序，请根据程序提示输入您的API地址，如果没有直接回车即可，但在查询时将不会调用相关模块')
        ThreatBook_api = input('请输入您的微步 Api：')
        Fofa_email = input('请输入您的Fofa邮箱：')
        Fofa_api = input('请输入您的Fofa Api：')
        ti360_cookie = input('请输入360威胁情报中心cookie ti_portal：')
        config_text = '''[Api Config]

# 微步威胁情报查询，查看 api 地址：https://x.threatbook.cn/nodev4/vb4/myAPI（每天 50 次的免费额度）
ThreatBook_api = '{ThreatBook_api}'

# Fofa ip 信息查询，查看 api 地址：https://fofa.so/personalData（付费，普通会员每次100条，高级会员每次10000条）
Fofa_email = '{Fofa_email}'
Fofa_api = '{Fofa_api}'
# 360威胁情报中心Cookie （暂无API支持）
ti360_cookie = '{ti360_cookie}'
'''.format(ThreatBook_api=ThreatBook_api, Fofa_email=Fofa_email, Fofa_api=Fofa_api, ti360_cookie=ti360_cookie)
        with open(config_path, 'w', encoding='utf-8-sig') as w:
            w.write(config_text)
    else:
        with open(config_path, encoding='utf-8-sig') as f:
            f = f.read()
        if 'Threat Intelligence' in f:
            console.log('检测存在历史版本配置文件，正在自动更新配置文件……')
            cfg = ConfigParser()
            cfg.read(config_path, encoding='utf-8-sig')
            ThreatBook_api = cfg.get('Threat Intelligence', 'ThreatBook_api').strip("'").strip()
            Fofa_email = cfg.get('IP Passive Information', 'Fofa_email').strip("'")
            Fofa_api = cfg.get('IP Passive Information', 'Fofa_api').strip("'").strip()
            config_text = '''[Api Config]

# 微步威胁情报查询，查看 api 地址：https://x.threatbook.cn/nodev4/vb4/myAPI（每天 50 次的免费额度）
ThreatBook_api = '{ThreatBook_api}'

# Fofa ip 信息查询，查看 api 地址：https://fofa.so/personalData（付费，普通会员每次100条，高级会员每次10000条）
Fofa_email = '{Fofa_email}'
Fofa_api = '{Fofa_api}'
'''.format(ThreatBook_api=ThreatBook_api, Fofa_email=Fofa_email, Fofa_api=Fofa_api)
            with open(config_path, 'w', encoding='utf-8-sig') as w:
                w.write(config_text)
            time.sleep(1)
            console.log('配置文件更新完成')
            time.sleep(1)
        elif 'Api Config' not in f:
            os.rename(config_path, config_path + '.bak')
            init(config_path)


def req(url, headers, proxies):
    try:
        r = requests.get(url, headers=headers, proxies=proxies, timeout=5, verify=False)
        return r
    except requests.exceptions.ConnectTimeout:
        if 'api.hackertarget.com' not in url:
            console.log('[red][EROR] 连接 %s 超时' % url)
        return 'Error'
    except requests.exceptions.ProxyError:
        console.log('[red][EROR] 连接代理失败' % url)
        return 'Error'
    except Exception as e:
        console.log('[red][EROR] 访问 %s 发生错误，错误信息： %s ' % (url, repr(e)))
        return 'Error'


def ThreatBook(ip, config_path):  # 微步威胁情报查询
    cfg = ConfigParser()
    cfg.read(config_path, encoding='utf-8-sig')
    ThreatBook_api = cfg.get('Api Config', 'ThreatBook_api').strip("'").strip()

    if ThreatBook_api == "":
        console.log('[red][EROR] 未检测到微步 API')
        return ('N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A')
    else:
        url = 'https://api.threatbook.cn/v3/scene/ip_reputation'
        query = {
            "apikey": "%s" % ThreatBook_api,
            "resource": "%s" % ip,
            "lang": "zh"
        }
        try:
            r = requests.request("GET", url, params=query, verify=False, proxies={'http': None, 'https': None})
            r_json = r.json()
            if r_json['response_code'] != 0:
                console.log('[red][EROR] 微步 API 调用失败，错误信息：%s' % r_json['verbose_msg'])
                return ('N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A')
            else:
                confidence_level = r_json['data']['%s' % ip]['confidence_level']  # 情报可信度
                if r_json['data']['%s' % ip]['is_malicious'] == False:  # 是否为恶意 IP
                    is_malicious = '否'
                else:
                    is_malicious = '是'
                severity = r_json['data']['%s' % ip]['severity']  # 危害程度
                judgments = ",".join(r_json['data']['%s' % ip]['judgments'])  # 威胁类型
                tags_classes = r_json['data']['%s' % ip]['tags_classes']  # 标签类别
                tags = []  # 标签
                tags_type = []  # 标签类型
                for i in tags_classes:
                    tags.append(",".join(i['tags']))
                    tags_type.append(i['tags_type'])
                tags = ','.join(tags)
                tags_type = ','.join(tags_type)
                scene = r_json['data']['%s' % ip]['scene']  # 场景
                carrier = r_json['data']['%s' % ip]['basic']['carrier']  # IP 基本信息
                location = r_json['data']['%s' % ip]['basic']['location']
                ip_location = location['country'] + ' ' + location['province'] + ' ' + location['city']  # IP 地理位置
                table = Table()
                table.add_column('是否为恶意IP', justify="center")
                table.add_column('危害程度', justify="center")
                table.add_column('威胁类型', justify="center")
                table.add_column('标签', justify="center")
                table.add_column('标签类型', justify="center")
                table.add_column('场景', justify="center")
                table.add_column('IP基本信息', justify="center")
                table.add_column('IP地理位置', justify="center")
                table.add_column('情报可信度', justify="center")
                table.add_row(is_malicious, severity, judgments, tags, tags_type, scene, carrier, ip_location,
                              confidence_level)
                console.log('[green][SUCC] %s 微步威胁情报信息：' % ip)
                console.print(table)
                return (
                    is_malicious, severity, judgments, tags, tags_type, scene, carrier, ip_location, confidence_level)
        except Exception as e:
            console.log('[red][EROR] 查询 %s 的微步信息发生错误，错误信息：%s' % (ip, repr(e)))
            return ('N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A')


def IP_survive(ip):
    os_name = os.name
    if os_name == 'nt':
        res = subprocess.call("ping -n 1 %s" % ip, shell=True, stdout=subprocess.PIPE)
    else:
        res = subprocess.call("ping -c 1 %s" % ip, shell=True, stdout=subprocess.PIPE)
    if res == 0:
        return 0
    else:
        return 1


def IP_reverse1(ip, proxies):
    url = 'http://api.hackertarget.com/reverseiplookup/?q=%s' % ip
    r = req(url, random_useragent(), proxies)
    if 'Error' != r:
        if 'API count exceeded - Increase Quota with Membership' not in r.text:  # 判断当前 IP 免费查询次数未用完，每个 IP 限制 100 条的免费查询限制
            IP_reverse1_list = []
            for i in r.text.split('\n'):
                if i != ip:
                    IP_reverse1_list.append(i)
                if IP_reverse1_list != []:
                    return IP_reverse1_list
                else:
                    return 0
        else:
            return 0
    else:
        return 0


def IP_reverse2(ip, proxies):
    url = 'http://api.webscan.cc/?action=query&ip=%s' % ip
    try:
        r = requests.get(url, headers=random_useragent(), proxies=proxies, timeout=5, verify=False)
    except:
        return 0
    if 'Error' != r:
        if r.text != 'null':
            IP_reverse2_list = []
            for ip in r.json():
                IP_reverse2_list.append(ip['domain'].strip())
            if IP_reverse2_list != []:
                return IP_reverse2_list
            else:
                return 0
        else:
            return 0
    else:
        return 0


def Fofa(ip, config_path):  # Fofa ip 信息查询
    cfg = ConfigParser()
    cfg.read(config_path, encoding='utf-8-sig')
    Fofa_email = cfg.get('Api Config', 'Fofa_email').strip("'")
    Fofa_api = cfg.get('Api Config', 'Fofa_api').strip("'").strip()

    if Fofa_api == "":
        console.log('[red][EROR] 未检测到Fofa API')
        if IP_survive(ip) == 0:
            IP_survive_bool = '是'
        else:
            IP_survive_bool = '否'
        return (IP_survive_bool, 0, 0)
    else:
        if IP_survive(ip) == 0:
            IP_survive_bool = '是'
        else:
            IP_survive_bool = '否'
        size = 100
        search_string_byte = base64.b64encode(ip.encode('utf-8')).decode()
        url = 'https://fofa.so/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=%s' % (
            Fofa_email, Fofa_api, search_string_byte, size)
        proxies = {'http': None, 'https': None}
        try:
            r = req(url, random_useragent(), proxies)
            r_json = r.json()
            if r_json['error'] == True:
                if r_json[
                    'errmsg'] == '401 Unauthorized, make sure 1.email and apikey is correct 2.FOFA coin is enough.':
                    console.log('[red][EROR] Fofa API 调用失败，错误原因有：1、Fofa 邮箱或 API 填写错误\t2、F币余额不足')
                else:
                    console.log('[red][EROR] Fofa 获取数据发生错误，错误信息：%s' % r_json['errmsg'])
                return (IP_survive_bool, 0, 0)
            elif len(r_json['results']) > 0:

                ip_port = []  # 获得 fofa 查询结果中的开放端口信息
                for i in r_json['results']:
                    ip_port.append(i[2])
                ip_port = list(set(ip_port))
                ip_port.sort(key=int)
                fofa_port = ",".join(ip_port)
                fofa_url_result = []  # 获得 fofa 查询结果中的域名信息
                for i in r_json['results']:
                    if ip not in i[0]:
                        if 'http://' not in i[0] and 'https://' not in i[0]:
                            fofa_url_result.append(i[0].split(':')[0])
                        else:
                            fofa_url_result.append(i[0].split('://')[1].split(':')[0] + '\n')
                return (IP_survive_bool, fofa_port, fofa_url_result)
            else:
                return (IP_survive_bool, 0, 0)
        except Exception as e:
            console.log('[red][EROR] 查询 %s 的 Fofa 信息发生错误，错误信息：%s' % (ip, repr(e)))
            return (IP_survive_bool, 0, 0)


# 360TI TEST version
s = requests.Session()


def init_360ti(config_path):
    cfg = ConfigParser()
    ti_portal = ""
    try:
        cfg.read(config_path, encoding='utf-8-sig')
        ti_portal = cfg.get('Api Config', 'ti360_cookie').strip("'").strip()
    except:
        console.log('[red][EROR] 未检测到360威胁情报Cookie查询可能会有限制')
        pass
    if ti_portal == "":
        console.log('[red][EROR] 未检测到360威胁情报Cookie查询可能会有限制')
    s.cookies.set("ti_portal", ti_portal)


def req_360ti(info_type, query):
    url = "https://ti.360.cn/ti/{}?query={}".format(info_type, query)
    try:
        r = s.get(url, headers=random_useragent(), timeout=5, verify=False)
    except requests.exceptions.ConnectTimeout:
        if 'api.hackertarget.com' not in url:
            console.log('[red][EROR] 连接 %s 超时' % url)
        return 'Error'
    except requests.exceptions.ProxyError:
        console.log('[red][EROR] 连接代理失败' % url)
        return 'Error'
    except Exception as e:
        console.log('[red][EROR] 访问 %s 发生错误，错误信息： %s ' % (url, repr(e)))
        return 'Error'
    s.cookies.update(r.cookies)
    return r.json()["data"]


def ti360(ip):  # 360威胁情报查询
    ti360_infos = {}
    query_dict = ["ip_info", "ip_rdns", "ip_ports"]
    ky_dict = ['ip_info', "ip_whois"]
    for t in query_dict:
        tmp = req_360ti(t, ip)
        if tmp is not None:
            ti360_infos[t] = tmp
    table = PrettyTable()
    dns_table = PrettyTable()
    port_table = PrettyTable()
    for t in ti360_infos:
        print("===== {} ====".format(t))
        i_data_list = []
        i_data_key = []
        for s, v in ti360_infos[t].items():
            if t in ky_dict:
                v_t = v['value']
                if s == "ips":
                    continue
                if s == "asn":
                    continue
                if s == "network_type":
                    v_t = v_t['type']
                if s == "tag":
                    str_s = ""
                    for t0, t1 in v_t.items():
                        str_s += (" ".join(t1) + " ")
                    v_t = str_s
                i_data_key.append(str(v['key']))
                i_data_list.append(v_t)
            elif t == "ip_rdns":
                i_data_key = ["域名", "DNS记录", "标签"]
                dns_table.field_names = tuple(i_data_key)
                ip_rdns_item = v['value']
                for v1 in ip_rdns_item:
                    str_s_s = ""
                    for t0, t1 in v1['tag'].items():
                        str_s_s += (" ".join(t1) + " ")
                    dns_table.add_row([v1['rrname'], v1['rrtype'], str_s_s])

        if t == "ip_ports":
            i_data_key = ["端口", "服务协议", "服务名称", "版本信息"]
            port_table.field_names = tuple(i_data_key)
            item = dict(ti360_infos["ip_ports"])['ip_ports']
            for v1 in item:
                port_table.add_row([v1['port'], v1['name'], v1['os_name'], v1['os_version']])

        if t in ky_dict:
            table.field_names = tuple(i_data_key)
            table.add_row(i_data_list)
            console.print(table)
        if t == "ip_rdns":
            console.print(dns_table)
        if t == "ip_ports":
            console.print(port_table)


# === 360 TEST END


def main(ip, config_path, proxies):
    init_360ti(config_path)
    ThreatBook_result = ThreatBook(ip, config_path)
    ti360(ip)
    IP_reverse_url = []
    IP_reverse1_result = IP_reverse1(ip, proxies)
    if IP_reverse1_result != 0:
        for i in IP_reverse1_result:
            if len(i) > 0:
                IP_reverse_url.append(i)
    IP_reverse2_result = IP_reverse2(ip, proxies)
    if IP_reverse2_result != 0:
        for i in IP_reverse2_result:
            if len(i) > 0:
                IP_reverse_url.append(i)
    fofa_result = Fofa(ip, config_path)
    IP_survive_bool = fofa_result[0]
    fofa_port = fofa_result[1]
    fofa_url_result = fofa_result[2]
    if fofa_port == 0:
        fofa_port = ''
    if fofa_url_result != 0:
        for i in fofa_url_result:
            if len(i) > 0:
                IP_reverse_url.append(i)
    table = Table()
    table.add_column(' IP 是否存活', justify="center")
    table.add_column(' IP 可能开放端口', justify="center")
    table.add_row(IP_survive_bool, fofa_port)
    console.log('[green][SUCC] %s 其他信息：' % ip)
    console.print(table)
    time.sleep(1)
    if len(IP_reverse_url) > 0:
        IP_reverse_url = list(set(IP_reverse_url))
        IP_reverse_url.sort()

        def domain_info():
            result = {}
            result['ip'] = ip
            result['是否为恶意IP'] = ThreatBook_result[0]
            result['危害程度'] = ThreatBook_result[1]
            result['威胁类型'] = ThreatBook_result[2]
            result['标签'] = ThreatBook_result[3]
            result['标签类型'] = ThreatBook_result[4]
            result['场景'] = ThreatBook_result[5]
            result['IP基本信息'] = ThreatBook_result[6]
            result['IP地理位置'] = ThreatBook_result[7]
            result['情报可信度'] = ThreatBook_result[8]
            result['IP是否存活'] = IP_survive_bool
            result['IP 可能开放端口'] = fofa_port
            try:
                url_icp = 'https://api.vvhan.com/api/icp?url=%s' % i
                r_icp = req(url_icp, random_useragent(), proxies)
                if 'Error' != r_icp:
                    r_icp_json = r_icp.json()
                    if 'message' not in r_icp_json:  # 存在备案信息
                        result['域名'] = i.strip()
                        result['标题'] = r_icp_json['info']['title'].strip()
                        result['备案类型'] = r_icp_json['info']['nature'].strip()
                        result['备案名称'] = r_icp_json['info']['name'].strip()
                        result['备案号'] = r_icp_json['info']['icp'].strip()
                    else:  # 不存在备案信息
                        result['域名'] = i.strip()
                        result['标题'] = 'N/A'
                        result['备案类型'] = 'N/A'
                        result['备案名称'] = 'N/A'
                        result['备案号'] = 'N/A'
            except Exception as e:
                console.log('[red][EROR] 查询 %s 的备案信息发生错误，错误信息：%s' % (i.strip(), repr(e)))
                result['域名'] = i.strip()
                result['标题'] = 'N/A'
                result['备案类型'] = 'N/A'
                result['备案名称'] = 'N/A'
                result['备案号'] = 'N/A'

            try:
                url_whois = 'https://api.devopsclub.cn/api/whoisquery?domain=%s&type=json' % i
                r_whois = req(url_whois, random_useragent(), proxies)
                if 'Error' != r_whois:
                    r_whois_json = r_whois.json()
                    r_whois_text = r_whois.text
                    if r_whois.status_code == 200:
                        if r_whois_json['msg'] != 'query fail':
                            if 'registrar' in r_whois_text:
                                result['注册人'] = r_whois_json['data']['data']['registrar']
                            elif 'registrant' in r_whois_text:
                                result['注册人'] = r_whois_json['data']['data']['registrant']
                            else:
                                result['注册人'] = 'N/A'

                            if 'registrarAbuseContactEmail' in r_whois_text:
                                result['注册邮箱'] = r_whois_json['data']['data']['registrarAbuseContactEmail']
                            elif 'registrantContactEmail' in r_whois_text:
                                result['注册邮箱'] = r_whois_json['data']['data']['registrantContactEmail']
                            else:
                                result['注册邮箱'] = 'N/A'

                            if 'registrarWHOISServer' in r_whois_text:
                                result['注册商'] = r_whois_json['data']['data']['registrarWHOISServer']
                            elif 'sponsoringRegistrar' in r_whois_text:
                                result['注册商'] = r_whois_json['data']['data']['sponsoringRegistrar']
                            else:
                                result['注册商'] = 'N/A'

                            if 'creationDate' in r_whois_text:
                                result['注册时间'] = \
                                    r_whois_json['data']['data']['creationDate'].split('T')[0]
                            elif 'registrationTime' in r_whois_text:
                                result['注册时间'] = \
                                    r_whois_json['data']['data']['registrationTime'].split(' ')[0]
                            else:
                                result['注册时间'] = 'N/A'

                            if 'registryExpiryDate' in r_whois_text:
                                result['到期时间'] = \
                                    r_whois_json['data']['data']['registryExpiryDate'].split('T')[0]
                            elif 'expirationTime' in r_whois_text:
                                result['到期时间'] = \
                                    r_whois_json['data']['data']['expirationTime'].split(' ')[0]
                            else:
                                result['到期时间'] = 'N/A'
                        else:
                            result['注册人'] = 'N/A'
                            result['注册邮箱'] = 'N/A'
                            result['注册商'] = 'N/A'
                            result['注册时间'] = 'N/A'
                            result['到期时间'] = 'N/A'
                    else:
                        result['注册人'] = 'N/A'
                        result['注册邮箱'] = 'N/A'
                        result['注册商'] = 'N/A'
                        result['注册时间'] = 'N/A'
                        result['到期时间'] = 'N/A'
            except Exception as e:
                console.log('[red][EROR] 查询 %s 的 Whois 信息发生错误，错误信息：%s' % (i.strip(), repr(e)))
                result['注册人'] = 'N/A'
                result['注册邮箱'] = 'N/A'
                result['注册商'] = 'N/A'
                result['注册时间'] = 'N/A'
                result['到期时间'] = 'N/A'
            pools.append(result)
            pools_single.append(result)

        pools_single = []
        if len(IP_reverse_url) > 3:
            console.log('[yellow][INFO] %s 反查到 %s 个 域名，正在查询域名相关信息，请稍等……' % (ip, len(IP_reverse_url)))
            for i in track(IP_reverse_url, description='域名信息查询进度：'):
                domain_info()
        else:
            for i in IP_reverse_url:
                domain_info()
        table = Table()
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
        for i in pools_single:
            table.add_row(i['域名'], i['标题'], i['备案类型'], i['备案名称'], i['备案号'], i['注册人'], i['注册邮箱'], i['注册商'],
                          i['注册时间'], i['到期时间'])
        console.log('[green][SUCC] %s 域名反查信息：' % ip)
        console.print(table)
    else:
        console.log('[yellow][INFO] 未查询到 %s 的反查域名' % ip)
        result = {}
        result['ip'] = ip
        result['是否为恶意IP'] = ThreatBook_result[0]
        result['危害程度'] = ThreatBook_result[1]
        result['威胁类型'] = ThreatBook_result[2]
        result['标签'] = ThreatBook_result[3]
        result['标签类型'] = ThreatBook_result[4]
        result['场景'] = ThreatBook_result[5]
        result['IP基本信息'] = ThreatBook_result[6]
        result['IP地理位置'] = ThreatBook_result[7]
        result['情报可信度'] = ThreatBook_result[8]
        result['IP是否存活'] = IP_survive_bool
        result['IP 可能开放端口'] = fofa_port
        result['域名'] = 'N/A'
        result['标题'] = 'N/A'
        result['备案类型'] = 'N/A'
        result['备案名称'] = 'N/A'
        result['备案号'] = 'N/A'
        result['注册人'] = 'N/A'
        result['注册邮箱'] = 'N/A'
        result['注册商'] = 'N/A'
        result['注册时间'] = 'N/A'
        result['到期时间'] = 'N/A'
        pools.append(result)


if __name__ == '__main__':
    console.print('''[bold blue]
+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
|T|h|r|e|a|t| |I|n|t|e|l|l|i|g|e|n|c|e| |G|a|t|h|e|r|i|n|g|
+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
    团队：狼组安全团队   作者：TeamsSix    版本：0.5.2       
    ''')
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', dest='config', help='指定配置文件，默认 ./config.ini')
    parser.add_argument('-f', dest='file', help='指定 IP 文本，一行一个')
    parser.add_argument('-i', dest='ip', help='指定目标 IP')
    parser.add_argument('-p', dest='proxy', help='指定代理，比如：http://127.0.0.1:1080 或者 socks5://127.0.0.1:1080')
    parser.add_argument('-o', dest='output', help='导出为 excel 表格，例如 output.xlsx')
    args = parser.parse_args()

    if args.config:
        config_path = args.config
        if not os.path.exists(config_path):
            console.log('[red][EROR] 未找到配置文件，请确认配置文件路径是否正确')
            sys.exit()
    else:
        root_path = sys.path[0]
        config_path = '%s/config.ini' % root_path
        init(config_path)

    if args.output:
        tig_output = args.output
        if os.path.exists(tig_output):
            console.log('[red][EROR] %s 文件已存在' % tig_output)
            sys.exit()
    else:
        root_path = sys.path[0]
        if not os.path.exists('%s/output' % root_path):
            os.mkdir('%s/output' % root_path)
        tig_output = '%s/output/tig_%s.xlsx' % (root_path, int(time.time()))
    if args.proxy:
        proxies = {'http': args.proxy, 'https': args.proxy}
    else:
        proxies = {'http': None, 'https': None}
    pools = []
    if args.ip:
        ip = args.ip
        console.rule("[yellow]正在查询 %s 的情报信息" % ip, style="yellow")
        main(ip, config_path, proxies)
    elif args.file:
        with open(args.file) as f:
            f = f.readlines()
        ip_list = []
        for i in f:
            i = i.strip()
            if '.' in i:
                ip_list.append(i)
        num = 0
        ip_len = len(ip_list)
        for i in ip_list:
            num = num + 1
            console.rule("[yellow]正在查询 %s 的情报信息，剩余 %s 个IP" % (i, ip_len - num), style="yellow")
            main(i, config_path, proxies)
            print()
    else:
        console.log('[yellow][INFO] 请输入待扫描的 IP 或 IP 列表文件')
        sys.exit()
    df = DataFrame(pools, columns=['ip', 'IP是否存活', 'IP 可能开放端口', '是否为恶意IP', '危害程度', '威胁类型', '标签', '标签类型', '场景', 'IP基本信息',
                                   'IP地理位置', '情报可信度', '域名', '注册人', '注册邮箱', '注册商', '注册时间', '到期时间'])
    df.to_excel(tig_output)
    time.sleep(1)
    console.log('[green][SUCC] 结果已保存至 %s' % tig_output)
