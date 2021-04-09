#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
# author TeamsSix
# blog https://www.teamssix.com
# github https://github.com/teamssix

import os
import sys
import time
import base64
import random
import openpyxl
import requests
import argparse
import threading
import subprocess
import pandas as pd
from pandas import DataFrame
from configparser import ConfigParser


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
    config_text = '''[Threat Intelligence]

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
IP_survive_enable = true'''
    with open(config_path, 'w', encoding='utf-8-sig') as w:
        w.write(config_text)


def print_list(list):
    print_text = ''
    for i in list:
        if i != list[-1]:
            print_text = print_text + i + ','
        else:
            print_text = print_text + i
    return print_text


def youdao_trans(text, proxies):
    url = 'http://fanyi.youdao.com/translate?&doctype=json&type=EN2ZH_CN&i=%s' % text
    r = requests.get(url, headers=random_useragent(), proxies=proxies)
    try:
        text_trans = r.json()['translateResult'][0][0]['tgt'].strip('。').strip('，')
        return text_trans.replace('城市', '市').replace('中国联合通信有限公司', '中国联通有限公司')
    except:
        return text


def req(url, headers, proxies):
    try:
        r = requests.get(url, headers=headers, proxies=proxies, timeout=5)
        return r
    except requests.exceptions.ConnectTimeout:
        if 'api.hackertarget.com' not in url:
            print('\n[-] 连接 %s 超时' % url)
        return 'Error'
    except requests.exceptions.ProxyError:
        print('\n[-] 连接代理失败' % url)
        return 'Error'
    except Exception as e:
        print('\n[!] 访问 %s 发生错误，错误信息： %s ' % (url, repr(e)))
        return 'Error'


def ThreatBook(ip, config_path):  # 微步威胁情报查询
    cfg = ConfigParser()
    cfg.read(config_path, encoding='utf-8-sig')
    ThreatBook_api = cfg.get('Threat Intelligence', 'ThreatBook_api').strip("'").strip()

    if ThreatBook_api == "":
        print('\n[-] 未检测到微步 API')
    else:
        url = 'https://api.threatbook.cn/v3/scene/ip_reputation'
        query = {
            "apikey": "%s" % ThreatBook_api,
            "resource": "%s" % ip
        }
        r = requests.request("GET", url, params=query)

        def tag_trans(tag):
            tag_list = ['Spam', 'Zombie', 'Scanner', 'Exploit', 'Botnet', 'Suspicious', 'Brute Force', 'Proxy',
                        'Whitelist',
                        'Info', 'C2', 'Hijacked', 'Phishing', 'Malware', 'Compromised', 'MiningPool', 'CoinMiner',
                        'Sinkhole C2', 'SSH Brute Force', 'FTP Brute Force', 'SMTP Brute Force', 'Http Brute Force',
                        'Web Login Brute Force', 'HTTP Proxy', 'HTTP Proxy In', 'HTTP Proxy Out', 'Socks Proxy',
                        'Socks Proxy In', 'Socks Proxy Out', 'VPN', 'VPN In', 'VPN Out', 'Tor', 'Tor Proxy In',
                        'Tor Proxy Out', 'Bogon', 'FullBogon', 'Gateway', 'IDC', 'Dynamic IP', 'Edu', 'DDNS', 'Mobile',
                        'Search Engine Crawler', 'CDN', 'Advertisement', 'DNS', 'BTtracker', 'Backbone']
            tag_trans = ['垃圾邮件', '傀儡机', '扫描', '漏洞利用', '僵尸网络', '可疑', '暴力破解', '代理', '白名单', '基础信息', '远控', '劫持', '钓鱼',
                         '恶意软件',
                         '失陷主机', '矿池', '私有矿池', '安全机构接管 C2', 'SSH暴力破解', 'FTP暴力破解', 'SMTP暴力破解', 'HTTP AUTH暴力破解', '撞库',
                         'HTTP Proxy', 'HTTP代理入口', 'HTTP代理出口', 'Socks代理', 'Socks代理入口', 'Socks代理出口', 'VPN代理', 'VPN入口',
                         'VPN出口', 'Tor代理', 'Tor入口', 'Tor出口', '保留地址', '未启用IP', '网关', 'IDC服务器', '动态IP', '教育', '动态域名',
                         '移动基站',
                         '搜索引擎爬虫', 'CDN服务器', '广告', 'DNS服务器', 'BT服务器', '骨干网']
            try:
                tag_index = tag_list.index(tag)
                return tag_trans[tag_index]
            except:
                return tag

        def scene_trans(scene):
            scene_list = ['CDN', 'University', 'Mobile Network', 'Unused', 'Unrouted', 'WLAN', 'Anycast',
                          'Infrastructure',
                          'Internet Exchange', 'Company', 'Hosting', 'Satellite Communication', 'Residence',
                          'Special Export', 'Institution', 'Cloud Provider']
            scene_trans = ['CDN', '学校单位', '移动网络', '已路由-未使用', '已分配-未路由', 'WLAN', 'Anycast', '基础设施', '交换中心', '企业专线',
                           '数据中心',
                           '卫星通信', '住宅用户', '专用出口', '组织机构', '云厂商']
            try:
                scene_index = scene_list.index(scene)
                return scene_trans[scene_index]
            except:
                return scene

        r_json = r.json()
        if r_json['response_code'] != 0:
            if r_json['verbose_msg'] == 'Beyond Daily Limitation':
                print('\n[-] 微步 API 已超出当日使用次数')
            else:
                print('\n[-] 微步 API 调用失败，错误信息：%s' % r_json['verbose_msg'])
        else:
            # 情报可信度
            confidence_level = r_json['data']['%s' % ip]['confidence_level']
            if confidence_level == 'low':
                confidence_level = '低'
            elif confidence_level == 'medium':
                confidence_level = '中等'
            elif confidence_level == 'high':
                confidence_level = '高'

            # 是否为恶意 IP
            if r_json['data']['%s' % ip]['is_malicious'] == False:
                is_malicious = '否'
            else:
                is_malicious = '是'

            # 危害程度
            severity = r_json['data']['%s' % ip]['severity']
            if severity == 'info':
                severity = '无'
            elif severity == 'low':
                severity = '低'
            elif severity == 'medium':
                severity = '中'
            elif severity == 'high':
                severity = '高'
            elif severity == 'critical':
                severity = '严重'

            # 微步标签
            tag_original = r_json['data']['%s' % ip]['judgments']

            # 标签类别
            tags_classes = r_json['data']['%s' % ip]['tags_classes']

            # 场景
            scene = r_json['data']['%s' % ip]['scene']

            # IP 基本信息
            carrier = r_json['data']['%s' % ip]['basic']['carrier']
            if carrier != '':
                carrier = youdao_trans(carrier, proxies)
            location = r_json['data']['%s' % ip]['basic']['location']
            if location['province'] in ['Shanghai', 'Beijing', 'Tianjin', 'Chongqing']:
                ip_location = location['country'] + ' ' + location['city']
            else:
                ip_location = location['country'] + ' ' + location['province'] + ' ' + location['city']
            ip_location = youdao_trans(ip_location, proxies)

            print('\n[+] 情报可信度：%s' % confidence_level)
            print('[+] 是否为恶意IP：%s' % is_malicious)
            print('[+] IP危害等级：%s' % severity)
            if len(tag_original) != 0:
                print('[+] 微步标签：', end='')
                for i in tag_original:
                    if i != tag_original[-1]:
                        print(tag_trans(i), end=',')
                    else:
                        print(tag_trans(i))
            if len(tags_classes) > 0:
                print('[+] 标签类别：', end='')
                print(print_list(tags_classes[0]['tags']))
                print('[+] 安全事件标签：%s' % tags_classes[0]['tags_type'])
            if scene != '':
                print('[+] 应用场景：%s' % scene_trans(scene))
            if carrier != '':
                print('[+] 运营商：%s' % carrier)
            print('[+] 地理位置：%s' % ip_location)
            print('[+] 情报更新时间：%s' % r_json['data']['%s' % ip]['update_time'])


def IP_survive(ip):
    os_name = os.name
    if os_name == 'nt':
        res = subprocess.call("ping -n 2 %s" % ip, shell=True, stdout=subprocess.PIPE)
    else:
        res = subprocess.call("ping -c 2 %s" % ip, shell=True, stdout=subprocess.PIPE)
    if res == 0:
        print('\n[+] %s 可以 ping 通' % ip)
    else:
        print('\n[-] %s 无法 ping 通，主机可能不存活' % ip)


def IP_reverse_print(ip, config_path, proxies):
    thread_list_str = threading.enumerate()
    thread_list = []
    for i in thread_list_str:
        i = str(i)
        if 'started' in i:
            i = i.split('(')[1].split(',')[0]
            thread_list.append(i)
    IP_reverse_url = []
    while not os.path.exists('.ip_reverse_mAJyXFfG.txt'):
        time.sleep(5)
    with open('.ip_reverse_mAJyXFfG.txt') as f:
        f = f.readlines()
    if 't_IP_reverse1' not in thread_list and 't_IP_reverse2' not in thread_list and 't_Fofa' not in thread_list:  # 判断反查域名是否获取完毕
        for url in f:
            url = url.strip()
            if url not in ['----api.hackertarget.com----', '----api.webscan.cc----', '----Fofa-API----']:
                IP_reverse_url.append(url)
        if len(IP_reverse_url) > 0:
            IP_reverse_url = list(set(IP_reverse_url))
            IP_reverse_url.sort()

            def print_IP_reverse_url():
                if len(IP_reverse_url) == 1:
                    print('\n[+] IP 反查域名信息：%s' % IP_reverse_url[0])
                else:
                    print('\n[+] IP 反查域名信息：')
                    for i in IP_reverse_url:
                        print(i)

            cfg = ConfigParser()
            cfg.read(config_path, encoding='utf-8-sig')
            ICP_beian_enable = cfg.get('IP Passive Information', 'ICP_beian_enable')
            Whois_enable = cfg.get('IP Passive Information', 'Whois_enable')

            if ICP_beian_enable == 'true' and Whois_enable == 'false':  # 只开启了 ICP 备案模块
                if len(IP_reverse_url) > 3:
                    print('\n[!] %s 反查到 %s 个 域名，正在查询域名相关信息，请稍等……' % (ip, len(IP_reverse_url)))

                pd.set_option('display.max_columns', 1000)
                pd.set_option('display.width', 1000)
                pd.set_option('display.max_colwidth', 1000)
                pd.set_option('display.unicode.ambiguous_as_wide', True)
                pd.set_option('display.unicode.east_asian_width', True)
                pools = []
                for i in IP_reverse_url:
                    result = {}
                    url = 'https://api.vvhan.com/api/icp?url=%s' % i
                    r_icp = req(url, random_useragent(), proxies)
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
                        pools.append(result)
                if len(pools) == 0:
                    print('\n[-] 未查询到 %s 反查域名的 ICP 备案信息' % ip)
                    print_IP_reverse_url()
                else:
                    df = DataFrame(pools, columns=['域名', '标题', '备案类型', '备案名称', '备案号'])
                    print('\n[+] IP 反查域名信息：')
                    print(df)

            elif ICP_beian_enable == 'false' and Whois_enable == 'true':  # 只开启了 Whois 信息模块
                if len(IP_reverse_url) > 3:
                    print('\n[!] %s 反查到 %s 个 域名，正在查询域名相关信息，请稍等……' % (ip, len(IP_reverse_url)))

                pd.set_option('display.max_columns', 1000)
                pd.set_option('display.width', 1000)
                pd.set_option('display.max_colwidth', 1000)
                pd.set_option('display.unicode.ambiguous_as_wide', True)
                pd.set_option('display.unicode.east_asian_width', True)
                pools = []
                for i in IP_reverse_url:
                    result = {}
                    url = 'https://api.devopsclub.cn/api/whoisquery?domain=%s&type=json' % i
                    r_whois = req(url, random_useragent(), proxies)
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
                                result['域名'] = i
                                result['注册人'] = 'N/A'
                                result['注册邮箱'] = 'N/A'
                                result['注册商'] = 'N/A'
                                result['注册时间'] = 'N/A'
                                result['到期时间'] = 'N/A'

                        else:
                            result['域名'] = i
                            result['注册人'] = 'N/A'
                            result['注册邮箱'] = 'N/A'
                            result['注册商'] = 'N/A'
                            result['注册时间'] = 'N/A'
                            result['到期时间'] = 'N/A'
                    pools.append(result)
                if len(pools) == 0:
                    print('\n[-] 未查询到 %s 反查域名的 Whois 信息' % ip)
                    print_IP_reverse_url()
                else:
                    df = DataFrame(pools, columns=['域名', '注册人', '注册邮箱', '注册商', '注册时间', '到期时间'])
                    print('\n[+] IP 反查域名信息：')
                    print(df)
            elif ICP_beian_enable == 'true' and Whois_enable == 'true':  # ICP 备案和 Whois 信息查询模块都开启
                if len(IP_reverse_url) > 3:
                    print('\n[!] %s 反查到 %s 个 域名，正在查询域名相关信息，请稍等……' % (ip, len(IP_reverse_url)))

                pd.set_option('display.max_columns', 1000)
                pd.set_option('display.width', 1000)
                pd.set_option('display.max_colwidth', 1000)
                pd.set_option('display.unicode.ambiguous_as_wide', True)
                pd.set_option('display.unicode.east_asian_width', True)
                pools = []
                for i in IP_reverse_url:
                    result = {}
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
                    pools.append(result)
                if len(pools) == 0:
                    print('\n[-] 未查询到 %s 反查域名的 Whois 和 ICP 备案信息' % ip)
                    print_IP_reverse_url()
                else:
                    df = DataFrame(pools,
                                   columns=['域名', '标题', '备案类型', '备案名称', '备案号', '注册人', '注册邮箱', '注册商', '注册时间',
                                            '到期时间'])
                    print('\n[+] IP 反查域名信息：')
                    print(df)
            elif ICP_beian_enable == 'false' and Whois_enable == 'false':  # ICP 备案和 Whois 信息查询模块都未开启
                print_IP_reverse_url()
            else:
                print('\n[!] 请检查配置文件中 ICP_beian_enable 或 Whois_enable 配置项是否设置错误，只能设置成 true 或 false')
        else:
            print('\n[-] 未查询到 %s 的反查域名' % ip)
    else:
        time.sleep(3)
        IP_reverse_print(ip, config_path, proxies)
    if os.path.exists('.ip_reverse_mAJyXFfG.txt'):
        os.remove('.ip_reverse_mAJyXFfG.txt')


def IP_reverse1(ip, proxies):
    url = 'http://api.hackertarget.com/reverseiplookup/?q=%s' % ip
    r = req(url, random_useragent(), proxies)
    if 'Error' != r:
        if 'API count exceeded - Increase Quota with Membership' not in r.text:  # 判断当前 IP 免费查询次数未用完，每个 IP 限制 100 条的免费查询限制
            IP_reverse_list = []
            for i in r.text.split('\n'):
                if i != ip:
                    IP_reverse_list.append(i)
                if IP_reverse_list != []:
                    with open('.ip_reverse_mAJyXFfG.txt', 'a') as w:
                        for ip in IP_reverse_list:
                            w.write(ip + '\n')
    with open('.ip_reverse_mAJyXFfG.txt', 'a') as w:
        w.write('----api.hackertarget.com----' + '\n')


def IP_reverse2(ip, proxies):
    url = 'http://api.webscan.cc/?action=query&ip=%s' % ip
    r = req(url, random_useragent(), proxies)
    if 'Error' != r:
        if r.text != 'null':
            with open('.ip_reverse_mAJyXFfG.txt', 'a') as w:
                for ip in r.json():
                    w.write(ip['domain'].strip() + '\n')
    with open('.ip_reverse_mAJyXFfG.txt', 'a') as w:
        w.write('----api.webscan.cc----' + '\n')


def Fofa(ip, config_path):  # Fofa ip 信息查询
    cfg = ConfigParser()
    cfg.read(config_path, encoding='utf-8-sig')
    Fofa_email = cfg.get('IP Passive Information', 'Fofa_email').strip("'")
    Fofa_api = cfg.get('IP Passive Information', 'Fofa_api').strip("'").strip()
    if Fofa_api == "":
        print('\n[-] 未检测到Fofa API')
    else:
        size = 100
        search_string_byte = base64.b64encode(ip.encode('utf-8')).decode()
        url = 'https://fofa.so/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=%s' % (
            Fofa_email, Fofa_api, search_string_byte, size)
        proxies = {'http': None, 'https': None}
        r = req(url, random_useragent(), proxies)
        r_json = r.json()
        if r_json['error'] == True:
            if r_json['errmsg'] == '401 Unauthorized, make sure 1.email and apikey is correct 2.FOFA coin is enough.':
                print('\n[-] Fofa API 调用失败，错误原因有：\n    1、Fofa 邮箱或 API 填写错误\n    2、F币余额不足')
            else:
                print('\n[-] Fofa 获取数据发生错误，错误信息：%s' % r_json['errmsg'])
        elif len(r_json['results']) > 0:
            ip_port = []
            for i in r_json['results']:
                ip_port.append(i[2])
            ip_port = list(set(ip_port))
            ip_port.sort(key=int)
            fofa_port = print_list(ip_port)
            print('\n[+] %s 可能开放端口：%s' % (ip, fofa_port))
            if tig_output != None:
                pools = [{'IP': ip, '端口': fofa_port}]
                df = pd.DataFrame(pools, columns=['IP', '端口'])
                wb = openpyxl.load_workbook(tig_output)
                writer = pd.ExcelWriter(tig_output, engine='openpyxl')
                writer.book = wb
                df.to_excel(writer, sheet_name='端口信息', index=None)
                writer.save()
                writer.close()

            with open('.ip_reverse_mAJyXFfG.txt', 'a') as w:
                for i in r_json['results']:
                    if ip not in i[0]:
                        if 'http://' not in i[0] and 'https://' not in i[0]:
                            w.write(i[0].split(':')[0] + '\n')
                        else:
                            w.write(i[0].split('://')[1].split(':')[0] + '\n')
    with open('.ip_reverse_mAJyXFfG.txt', 'a') as w:
        w.write('----Fofa-API----' + '\n')


def main(ip, config_path, proxies):
    thread_list_str = threading.enumerate()
    thread_list = []
    for i in thread_list_str:
        i = str(i)
        if 'started' in i:
            i = i.split('(')[1].split(',')[0]
            thread_list.append(i)
    while len(thread_list) != 1:
        thread_list_str = threading.enumerate()
        thread_list = []
        for i in thread_list_str:
            i = str(i)
            if 'started' in i:
                i = i.split('(')[1].split(',')[0]
                thread_list.append(i)
        time.sleep(5)
    print('\n[!] 正在查询 %s 的情报信息--------------------------------------------' % ip)
    cfg = ConfigParser()
    cfg.read(config_path, encoding='utf-8-sig')
    ThreatBook_enable = cfg.get('Threat Intelligence', 'ThreatBook_enable')
    IP_reverse_enable = cfg.get('IP Passive Information', 'IP_reverse_enable')
    Fofa_enable = cfg.get('IP Passive Information', 'Fofa_enable')
    IP_survive_enable = cfg.get('IP Active Information', 'IP_survive_enable')

    if os.path.exists('.ip_reverse_mAJyXFfG.txt'):
        os.remove('.ip_reverse_mAJyXFfG.txt')

    if ThreatBook_enable == 'true':
        t_ThreatBook = threading.Thread(target=ThreatBook, args=(ip, config_path,), name='t_ThreatBook')
        t_ThreatBook.start()
    if IP_survive_enable == 'true':
        t_IP_survive = threading.Thread(target=IP_survive, args=(ip,), name='t_IP_survive')
        t_IP_survive.start()
    if IP_reverse_enable == 'true':
        t_IP_reverse1 = threading.Thread(target=IP_reverse1, args=(ip, proxies,), name='t_IP_reverse1')
        t_IP_reverse1.start()
        t_IP_reverse2 = threading.Thread(target=IP_reverse2, args=(ip, proxies,), name='t_IP_reverse2')
        t_IP_reverse2.start()
        time.sleep(5)
        t_IP_reverse_print_mark = 1
        while (t_IP_reverse_print_mark):
            if os.path.exists('.ip_reverse_mAJyXFfG.txt'):
                t_IP_reverse_print_mark = 0
                t_IP_reverse_print = threading.Thread(target=IP_reverse_print, args=(ip, config_path, proxies,),
                                                      name='t_IP_reverse_print')
                t_IP_reverse_print.start()
            else:
                time.sleep(5)

    if Fofa_enable == 'true':
        t_Fofa = threading.Thread(target=Fofa, args=(ip, config_path,), name='t_Fofa')
        t_Fofa.start()


if __name__ == '__main__':
    print('''
 +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
 |T|h|r|e|a|t| |I|n|t|e|l|l|i|g|e|n|c|e| |G|a|t|h|e|r|i|n|g|
 +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
    Author: TeamsSix    Version: 0.4.2    Date: 2021-04-09   
    ''')
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', dest='config', help='指定配置文件，默认 ./config.ini')
    parser.add_argument('-f', dest='file', help='IP 文本，一行一个')
    parser.add_argument('-i', dest='ip', help='目标 IP')
    parser.add_argument('-p', dest='proxy', help='指定代理，比如：http://127.0.0.1:1080 或者 socks5://127.0.0.1:1080')
    parser.add_argument('-o', dest='output', help='导出为excel表格，例如 output.xlsx')
    args = parser.parse_args()

    if args.config:
        config_path = args.config
    else:
        root_path = sys.path[0]
        config_path = '%s/config.ini' % root_path
        if not os.path.exists(config_path):
            init(config_path)
            print('[!] 未检测到配置文件，已自动生成配置文件，请修改配置文件后重新运行')
            sys.exit()

    if not os.path.exists(config_path):
        print('[-] 未找到配置文件，请确认配置文件路径是否正确')
        sys.exit()

    global tig_output
    if args.output:
        tig_output = args.output
        if os.path.exists(tig_output):
            print('[-] %s 文件已存在' % tig_output)
            sys.exit()
        tig_output_excel = pd.DataFrame()
        tig_output_excel.to_excel(tig_output)

    else:
        tig_output = None

    if args.proxy:
        proxies = {'http': args.proxy, 'https': args.proxy}
    else:
        proxies = {'http': None, 'https': None}

    if args.ip:
        main(args.ip, config_path, proxies)
    elif args.file:
        with open(args.file) as f:
            f = f.readlines()
        ip_list = []
        for i in f:
            i = i.strip()
            if '.' in i:
                ip_list.append(i)
        for i in ip_list:
            main(i, config_path, proxies)
    else:
        print('[!] 请输入待扫描的 IP 或 IP 列表文件')
        sys.exit()
