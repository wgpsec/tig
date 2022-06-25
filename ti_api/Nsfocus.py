import traceback
from json.decoder import JSONDecodeError
from rich.console import Console
# 导入自定义模块
from common.req import req
from common.random_ua import random_useragent

console = Console()


def nsfocus(ip, api_key, table):
    """
    微步威胁情报查询，微步单一 API 接口默认请求 50 次，如果超过 50 次，将提示 API 请求超限

    :param ip:              查询 IP
    :param api_key:         API key，string 类型
    :param table:           格式化输出富文本表格
    :return:
        is_malicious:       是否为恶意 IP
        threat_level:       危害程度
        threat_type:        威胁类别
        tags:               标签
        tags_type:          标签类别
        scene:              场景
        carrier:            运营商
        ip_location:        ip 地理位置
        credit_level:       可信度
        source              情报来源
    """
    # 全局变量，响应体
    global r

    # 返回值初始化
    is_malicious = 'N/A'
    threat_level = 'N/A'
    threat_type = 'N/A'
    tags = 'N/A'
    tags_type = 'N/A'
    scene = 'N/A'
    carrier = 'N/A'
    ip_location = 'N/A'
    credit_level = 'N/A'
    source = '绿盟'

    if api_key == "":
        console.log('[red][EROR] 未检测到绿盟 API[/red]')
        return table, [is_malicious, threat_level, threat_type, tags, tags_type, scene, carrier, ip_location,
                       credit_level, source]
    else:
        try:
            # 请求 IP 信誉
            ipv4_indicator_url = 'https://ti.nsfocus.com/api/v2/objects/ip-details/'
            query = {
                "type": "indicator",
                "query": ip,
            }
            header = {
                "X-Ns-Nti-Key": api_key,
            }
            header.update(random_useragent())

            r = req(ipv4_indicator_url,
                    headers=header,
                    params=query,
                    proxies={'http': None, 'https': None})
            if r:
                r_json = r.json()
                # 判断是否查询到，type 字段为查询结果必填字段
                if 'type' in r_json:
                    # 判断 查询结果计数，未查询到时 为 0
                    if r_json['count'] == 0:
                        source = '绿盟'
                        is_malicious = '暂无数据'
                        threat_level = '暂无数据'
                        threat_type = '暂无数据'
                        tags = '暂无数据'
                        tags_type = '暂无数据'
                        scene = '暂无数据'
                        credit_level = '暂无数据'
                    # 查询结果 非 0 时，取第一组可信度最高的数据
                    else:
                        """
                        {
                            "count": 1,
                            "spec_version": "2.0",
                            "objects": [
                                {
                                    "valid_until": "2022-09-09T09:00:04Z",
                                    "confidence": 30,
                                    "threat_level": 1,
                                    "revoked": false,
                                    "credit_level": 3,
                                    "pattern": "[ipv4-addr:value = '45.155.204.132']",
                                    "tags": [
                                        {
                                            "tag_values": [
                                                "outbound",
                                                "inbound"
                                            ],
                                            "tag_type": "direction"
                                        }
                                    ],
                                    "modified": "2022-06-18T10:11:49.000Z",
                                    "created_by": "nsfocus",
                                    "observables": [
                                        {
                                            "type": "ipv4-addr",
                                            "value": "45.155.204.132"
                                        }
                                    ],
                                    "threat_types": [
                                        9
                                    ],
                                    "act_types": [
                                        0
                                    ],
                                    "type": "indicator",
                                    "id": "0c9018aa6245de8909001",
                                    "categories": [
                                        "ip"
                                    ]
                                }
                            ],
                            "type": "bundle"
                        }
                        
                        """
                        # 查询到结果时，由于返回数据为一个数组格式，且结果基于 confidence 可信度排序，因此只取第一组可信度最高的数据
                        data = r_json['objects'][0]
                        # 来源，"created_by": "nsfocus"
                        source = data['created_by']

                        # 信誉等级（情报可信度）
                        dic = {5: '高', 3: '中', 1: '低', 0: '安全', -1: '未知'}
                        credit_level = dic[data['credit_level']]

                        # 判断是否为 恶意 IP，"categories": [ "ip" ]
                        if 'ip' in data['categories']:
                            is_malicious = '是'
                        else:
                            is_malicious = '否'

                        # 危害程度，"threat_level": 3
                        threat_level = dic[data['threat_level']]

                        # 威胁类型，"threat_types": [ 401 ]
                        dic = {1: "恶意软件", 101: "广告软件", 102: "木马", 103: "病毒", 104: "僵尸网络",
                               105: "勒索软件", 106: "后门", 107: "Ddos 工具", 108: "投放工具", 109: "漏洞利用工具",
                               110: "键盘记录器", 111: "远程控制木马", 112: "资源盗用软件", 113: "流氓软件", 114:
                                   "Rootkit", 115: "抓屏工具", 116: "间谍软件", 117: "蠕虫", 118: "风险软件", 119: "挖矿",
                               2: "缓冲区溢出", 3: "拒绝服务", 301: "主机 ddos", 30101: "资源占用", 30102: "主机破坏",
                               302: "网络 ddos", 30201: "IP 欺骗", 30202: "SYN Flood", 30203: "ACK Flood",
                               30204: "UDP Flood", 30205: "ICMP Flood", 30206: "IGMP Flood", 30207: "HTTP Flood",
                               30208: "HTTPS Flood", 30209: "DNS 请求 Flood", 30210: "DNS 应答 Flood", 30211: "SIP Flood",
                               30212: "NTP 反射 FLOOD", 30213: "SSDP 反射 FLOOD", 30214: "SNMP 反射 FLOOD",
                               30215: "CHARGEN 反射 FLOOD", 30216: "HTTP 慢速攻击", 4: "网络攻击", 401: "扫描探测",
                               402: "欺骗模仿", 40201: "WEP 破解", 403: "会话劫持", 40301: "跨站脚本", 40302: "中间人攻击",
                               404: "无线攻击", 40401: "参数篡改", 405: "Web 攻击", 40501: "Cookie 篡改", 40502: "命令注入",
                               40503: "SQL 注入", 40504: "SSRF", 40505: "CSRF", 40506: "路径穿越", 40507: "信息泄露",
                               40508: "Webshell", 406: "数据库攻击", 407: "僵尸网络", 40701: "僵尸主机", 40702: "C2 主机",
                               408: "垃圾邮件", 409: "攻陷网站", 5: "漏洞利用", 501: "软件 bug", 50101: "缓冲区溢出",
                               502: "配置不当", 503: "口令窃取", 50301: "弱口令", 50302: "暴力破解", 50303: "撞库攻击",
                               505: "数据嗅探", 506: "设计缺陷", 507: "系统攻击", 6: "物理攻击", 601: "基础攻击",
                               602: "能量武器", 60201: "高能快速成形", 60202: "大量放射性早期释放频率", 60203: "电磁脉冲",
                               7: "监控事件", 701: "行为监控", 8: "关注内容", 801: "非法内容", 80101: "钓鱼与欺诈",
                               80103: "盗用网站", 80105: "垃圾邮件网站", 80110: "恶意内容网站", 80111: "钓鱼", 80112: "欺诈",
                               8011201: "贷款诈骗", 8011202: "刷单诈骗", 8011203: "色情诈骗", 8011204: "网络赌博诈骗",
                               8011205: "冒充公检法诈骗", 8011206: "投资理财诈骗", 8011207: "冒充客服诈骗", 8011208: "虚假购物诈骗",
                               8011209: "注销校园贷诈骗", 8011210: "买卖游戏币诈骗", 8011211: "ETC 类诈骗", 8011212: "其他诈骗",
                               802: "敏感内容", 80202: "代理", 80203: "匿名网站", 80212: "矿池", 80213: "矿机", 9: "其他"
                               }
                        threat_type_list = data['threat_types']
                        threat_type = ""
                        for i in threat_type_list:
                            threat_type += f"{dic[i]},"
                        threat_type = threat_type.strip(",")

                        # 标签 "tags": [ { "tag_values": [ "inbound" ], "tag_type": "direction" } ]
                        # 标签类别
                        tags_list = data['tags']
                        # 初始化 tags，tags_type
                        tags = []  # 标签
                        tags_type = ""  # 标签类型
                        for i in tags_list:
                            tags += i.get('tag_values', 'N/A')
                            tags_type += f"{i.get('tag_type', 'N/A')},"
                        # tags 转 string 类型，最终用 "," 隔开
                        tags = ','.join(tags)
                        # 删除最后字符串头尾的","
                        tags_type = tags_type.strip(",")

                        # 绿盟无此参数
                        scene = 'N/A'
                elif 'error' in r_json:
                    """
                    {
                        "error": "Format error"
                    }
                    """
                    console.log(f"[red][EROR] 绿盟 ip 信誉查询失败，失败原因数据：{r_json['error']}[/red]")
                else:
                    console.log(f"[red][EROR] 绿盟 ip 信誉 API json 解析成功，"
                                f"但无 error 与 type 类型，原始数据：{r_json}[/red]")

            # 请求地理位置等 IP 基本信息
            ip_basic_url = 'https://ti.nsfocus.com/api/v2/objects/ip-details/'
            query = {
                "type": "ip-basic",
                "query": ip,
            }
            header = {
                "X-Ns-Nti-Key": api_key,
            }
            header.update(random_useragent())
            r = req(ip_basic_url,
                    headers=header,
                    params=query,
                    proxies={'http': None, 'https': None})
            if r:
                r_json = r.json()
                # 判断是否查询到，type 字段为查询结果必填字段
                if 'type' in r_json:
                    # 判断 查询结果计数，未查询到时 为 0
                    if r_json['count'] == 0:
                        console.log(f"[red][EROR] 绿盟 ip-basic API 调用失败，原始数据：{r_json} [/red]")
                    elif 'locations' in r_json['objects'][0]:
                        """
                        {
                            "count": 1,
                            "spec_version": "2.0",
                            "objects": [
                                {
                                    "ases": [
                                        {
                                            "name": "SELECTEL, RU",
                                            "registered": [
                                                "2009-06-18T00:00:00.000Z"
                                            ],
                                            "number": "AS49505",
                                            "country_code": "RU",
                                            "first_seen": "2022-04-16T06:20:00.000Z",
                                            "last_seen": "2022-06-16T06:26:47.000Z"
                                        }
                                    ],
                                    "object": {
                                        "type": "ipv4-addr",
                                        "value": "45.155.204.146"
                                    },
                                    "locations": [
                                        {
                                            "city": "Moscow",
                                            "country_code": "RU",
                                            "area": "",
                                            "latitude": "55.755847",
                                            "country": "Russia",
                                            "region": "Moscow",
                                            "isp": "OOO \"\"Network of data-centers \"\"Selectel\"\"",
                                            "longitude": "37.611856"
                                        }
                                    ],
                                    "created_by": "nsfocus",
                                    "modified": "2022-06-05T10:10:13.654Z",
                                    "service_count": 4,
                                    "services": [
                                        {
                                            "banner": "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\nkey type: ssh-rsa\nkey: AAAAB3NzaC1yc2EAAAADAQABAAABAQCZdJy24q4Y3CSN4aULZQRxIU5Z8qNE4YqOl1E/D4AeVA0lUrtAjOFq5H0gHtcMfvrayjvM7inbpeNwS+BYd8REDsRsa5jf/ezuElUi+UY9CVauCd7bdBMvKXxEp49LqqupU8S8lv2TfvVKjtbmYfgNu6KV19A2FKAhu4CQ9w9bpsVpHVi5vxU69cwgUUudg2Tc3fze0GrAQfnWFNXFlsLAHCGA9KS93kZAt6vJnL0ugYamEUCLFn7VjZyLJmGnhkg/bI9PkZfkDe8TU4M1z3e/8fXp/jE34iNK90CWLfCLL+oOtZqgY9i+SvosAszHvqEwXCDJBAoqMS7k6e2yJ6EL",
                                            "first_seen": "2022-04-25T02:51:51.000Z",
                                            "transport": {
                                                "port": 22,
                                                "protocols": [
                                                    "ipv4",
                                                    "tcp",
                                                    "ssh"
                                                ]
                                            },
                                            "last_seen": "2022-04-25T02:51:51.000Z"
                                        },
                                        {
                                            "first_seen": "2022-04-24T22:32:56.000Z",
                                            "banner": "NTP Version 4\n$йpЉ]жВћч&їµ≈O#Kq±RужГ\"6х•жГ\"@љ",
                                            "transport": {
                                                "port": 123,
                                                "protocols": [
                                                    "ipv4",
                                                    "udp",
                                                    "ntp 4"
                                                ]
                                            },
                                            "last_seen": "2022-04-24T22:32:56.000Z"
                                        },
                                        {
                                            "banner": "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u4\nkey type: ssh-rsa\nkey: AAAAB3NzaC1yc2EAAAADAQABAAABAQCnbM02ceXR+PEoUIC5GV0EqS5S83esS8IJYkXwsLRKXjBO8nwHC21Cpay66w34xFh/+yFpcxetiCpkZB43aptoZHz+/j+OV+PsNQYaFpP0uKRUvW8eF11OrIWfLRJGKJef9Mb2xAtOGlTsFEEjAVR/UbHUBO1+WliiqGzcnjHYMn+R3aVYRZdYnwnZUTX2SxVNvJjgGiMhH2t4fOL24z2PHpIkg0dQqGxsCDpkxCpP+jD8VuWNIg6UvUbvVe2KXPlhkcOFUUFiyUMsdPgGkWyXyorIQT7x/3Hce8XtIRormK2F5ay6kUFbmzwN5Pg/cj9p8fnCXcEvprJ5LQm4LwC5",
                                            "first_seen": "2020-03-19T08:00:00.000Z",
                                            "transport": {
                                                "port": 3389,
                                                "protocols": [
                                                    "ipv4",
                                                    "tcp",
                                                    "ssh"
                                                ]
                                            },
                                            "last_seen": "2020-03-19T08:00:00.000Z"
                                        },
                                        {
                                            "first_seen": "2020-02-02T00:00:00.000Z",
                                            "banner": "5mTeA1nkY78aE3hrxeAwPQ==",
                                            "transport": {
                                                "port": 8088,
                                                "protocols": [
                                                    "ipv4",
                                                    "tcp"
                                                ]
                                            },
                                            "last_seen": "2020-02-02T00:00:00.000Z"
                                        }
                                    ],
                                    "whoises": [
                                        {
                                            "last_updated": "2021-02-14T21:31:12.000Z",
                                            "contacts": [
                                                {
                                                    "phone_number": "+000000000",
                                                    "last_updated": "2020-05-18T22:01:41.000Z",
                                                    "name": "ABUSE APNICAP",
                                                    "country": "ZZ",
                                                    "remarks": [
                                                        "remarks: Generated from irt object IRT-APNIC-AP"
                                                    ],
                                                    "managed": "APNIC-ABUSE",
                                                    "email_address": "helpdesk@apnic.net",
                                                    "street_address": "Brisbane, Australia"
                                                },
                                                {
                                                    "phone_number": "",
                                                    "last_updated": "2018-06-22T14:34:30.000Z",
                                                    "name": "Internet Assigned Numbers Authority",
                                                    "remarks": [
                                                        "remarks: For more information on IANA services,go to IANA web site at http://www.iana.org."
                                                    ],
                                                    "managed": "MAINT-APNIC-AP",
                                                    "email_address": "",
                                                    "street_address": "see http://www.iana.org."
                                                }
                                            ],
                                            "irt": {
                                                "phone_number": "",
                                                "last_updated": "2020-02-02T18:04:33.000Z",
                                                "name": "IRT-APNIC-AP",
                                                "tech_c": "NO4-AP",
                                                "admin_c": "HM20-AP",
                                                "abuse_c": "helpdesk@apnic.net",
                                                "remarks": [
                                                    "remarks: APNIC is a Regional Internet Registry.,We do not operate the referring network and,are unable to investigate complaints of network abuse.,For information about IRT, see www.apnic.net/irt,helpdesk@apnic.net was validated on 2020-02-03"
                                                ],
                                                "managed": "APNIC-HM",
                                                "email_address": "helpdesk@apnic.net",
                                                "street_address": "Brisbane, Australia"
                                            },
                                            "modified": "2022-03-21T03:41:11.556Z",
                                            "net_range": "45.0.0.0 - 45.255.255.255",
                                            "net_type": "ALLOCATED PORTABLE",
                                            "net_name": "IANA-NETBLOCK-45",
                                            "remarks": [
                                                "mnt_by: APNIC-HM",
                                                "mnt_lower: APNIC-HM",
                                                "mnt_irt: IRT-APNIC-AP",
                                                "remarks: For general info on spam complaints email spam@apnic.net.,For general info on hacking & abuse complaints email abuse@apnic .net."
                                            ],
                                            "organization": {
                                                "tech_c": "",
                                                "admin_c": "",
                                                "name": ""
                                            },
                                            "first_seen": "2021-02-14T21:31:12.000Z",
                                            "last_seen": "2021-02-14T21:31:12.000Z"
                                        }
                                    ],
                                    "type": "ip-basic",
                                    "id": "0102d9bcc926527003000"
                                }
                            ],
                            "type": "bundle"
                        }
                        """
                        locations = r_json['objects'][0]['locations'][0]
                        # IP 运营商
                        carrier = locations['isp']
                        # IP 地理位置
                        ip_location = f"{locations['country']} - {locations['region']} - {locations['city']}"
                    # 如果没有 locations 关键词，取 ases 相应的字段
                    elif 'ases' in r_json['objects'][0]:
                        ases = r_json['objects'][0]['ases'][0]
                        # IP 运营商，取 AS 号
                        carrier = f" AS 号：{ases['number']}"
                        # IP 地理位置
                        ip_location = f"国度：{ases['country_code']}"
                    # 如果都没有，取默认值
                    else:
                        carrier = '暂无数据'
                        ip_location = '暂无数据'
                    # 添加进表格数据中
                    console.log(f"[green][SUCC] {ip} 绿盟威胁情报信息解析成功：[/green]")
                    table.add_row(source, is_malicious, threat_level, threat_type, tags, tags_type, scene, carrier,
                                  ip_location, credit_level)
                    return table, [is_malicious, threat_level, threat_type, tags, tags_type, scene, carrier,
                                   ip_location, credit_level, source]
                elif 'error' in r_json:
                    """
                    {
                        "error": "Format error"
                    }
                    """
                    console.log(f"[red][EROR] 绿盟 ip 基本信息查询失败，失败原因数据：{r_json['error']}[/red]")
                else:
                    console.log(f"[red][EROR] 绿盟 ip 基本信息 API json 解析成功，但无 error 与 type 类型，"
                                f"原始数据:{r_json}[/red]")
        except JSONDecodeError:
            console.log(f"[red][EROR] 绿盟威胁情报 API json 解析失败，原始内容：{r.text}[/red]")
        except Exception:
            console.log(f"[red][EROR] 查询 {ip} 的绿盟威胁情报发生程序错误，错误信息：{traceback.format_exc()} [/red]")
        # 所有异常返回当前查询到的所有值
        return table, [is_malicious, threat_level, threat_type, tags, tags_type, scene, carrier, ip_location,
                       credit_level, source]
