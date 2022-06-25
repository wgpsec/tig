import traceback

import requests
from rich.console import Console
from common.random_ua import random_useragent
from common.req import req

console = Console()


def threatbook(ip, api_key_chain, table):
    """
    微步威胁情报查询，微步单一 API 接口默认请求 50 次，如果超过 50 次，将提示 API 请求超限

    :param ip:              查询 IP
    :param api_key_chain:   API key 钥匙列表，list 类型
    :param table:           格式化输出富文本表格
    :return:
        is_malicious:       是否为恶意 IP
        severity:           危害程度     
        judgments:          威胁类别
        tags:               标签
        tags_type:          标签类别
        scene:              场景
        carrier:            运营商
        ip_location:        ip 地理位置
        confidence_level:   可信度
        source              情报来源
    """
    for api_key in api_key_chain:
        # 去除首尾两端的 "'"
        api_key = api_key.strip("'")
        if api_key == "":
            console.log('[red][EROR] 未检测到微步 API[/red]')
            return table, ['N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A']
        else:
            url = 'https://api.threatbook.cn/v3/scene/ip_reputation'
            query = {
                "apikey": api_key,
                "resource": ip,
                "lang": "zh"
            }
            try:
                r = req(url,
                        headers=random_useragent(),
                        params=query,
                        proxies={'http': None, 'https': None})
                r_json = r.json()
                if r_json['response_code'] == 0:
                    """data demo
                    {
                        "data": {
                            "159.203.93.255": {
                                "severity": "info",
                                "judgments": [
                                    "IDC"
                                ],
                                "tags_classes": [],
                                "basic": {
                                    "carrier": "digitalocean.com",
                                    "location": {
                                        "country": "United States",
                                        "province": "New York",
                                        "city": "New York City",
                                        "lng": "-74.006",
                                        "lat": "40.713",
                                        "country_code": "US"
                                    }
                                },
                                "asn": {
                                    "rank": 2,
                                    "info": "DIGITALOCEAN-ASN - DigitalOcean, LLC, US",
                                    "number": 14061
                                },
                                "scene": "",
                                "confidence_level": "low",
                                "is_malicious": false,
                                "update_time": "2016-05-17 20:18:33"
                            }
                        },
                        "response_code": 0,
                        "verbose_msg": "OK"
                    }
                    """
                    source = '微步'
                    data_list = r_json['data'][ip]
                    # 可信度。通过情报来源及可信度模型判别出来的恶意可信度程度，分"low（低）"，"medium（中）"，"high（高）" 三档来标识。
                    confidence_level = data_list['confidence_level']

                    # 是否为恶意 IP。布尔类型，true 代表恶意，false 代表非恶意。
                    if not data_list['is_malicious']:
                        is_malicious = '否'
                    else:
                        is_malicious = '是'

                    """严重级别。
                    表示该情报的危害程度，分为
                        "critical（严重）"，
                        "high（高）"，
                        "medium（中）"，
                        "low（低）"，
                        "info（无危胁）"
                    5 种程度类型。
                    """
                    severity = data_list['severity']

                    """从威胁情报中分析，提取出来的综合判定威胁类型，JSON 数组。
                    该接口中判定为恶意的类型含：
                        Spam：垃圾邮件
                        Zombie：傀儡机
                        Scanner：扫描
                        Exploit：漏洞利用
                        Botnet：僵尸网络
                        Suspicious：可疑
                        Brute Force：暴力破解
                        Brute Force 子类相关，参见：" 威胁类型全集"中描述。
                        Proxy：代理
                        Proxy 子类相关，参见：" 威胁类型全集"中描述。
                    该接口中判定为非恶意的类型含：
                        Whitelist：白名单。
                        Info：基础信息。
                    """
                    judgments = ",".join(data_list['judgments'])

                    """标签类别。相关攻击团伙或安全事件信息，JSON 数组，每个 item 包含字段说明如下：
                        tags_type：标签类别，如"industry(行业)"、"gangs（团伙）"、"virus_family（家族）"等。
                        tags：具体的攻击团伙或安全事件标签，例如：APT、海莲花等。
                    """
                    tags_classes = data_list['tags_classes']

                    # tags 默认是 list 类型，tags_type 默认是 string 类型，
                    # 尽可能少的转化变量类型，因此选择使用与返回值一样的类型用于拼接
                    tags = []
                    tags_type = ""
                    for i in tags_classes:
                        tags += i.get('tags', "N/A")
                        tags_type += f"{i.get('tags_type', 'N/A')},"
                    # tags 转 string 类型，最终用 "," 隔开
                    tags = ','.join(tags)
                    # 删除最后字符串头尾的","
                    tags_type = tags_type.strip(",")

                    # 应用场景。如：企业专线，数据中心等。
                    scene = data_list['scene']

                    """basic 返回是一个 JSON 对象，字段说明如下：
                    carrier: 运营商
                    location: ip 对应的位置信息，JSON 对象，说明如下：
                        country: 国家
                        country_code: 国家代码
                        province: 省
                        city: 城市
                        lng: 经度
                        lat: 纬度
                    """
                    # 运营商
                    carrier = data_list['basic']['carrier']

                    # ip 对应的位置信息
                    location = data_list['basic']['location']
                    ip_location = f"{location['country']} - {location['province']} - {location['city']}"

                    # 添加 表格行信息
                    table.add_row(source, is_malicious, severity, judgments, tags, tags_type, scene,
                                  carrier, ip_location, confidence_level)
                    console.log(f"[green][SUCC] {ip} 微步威胁情报信息解析成功：[/green]")
                    return table, [is_malicious, severity, judgments, tags, tags_type, scene, carrier,
                                   ip_location, confidence_level, source]
                # 返回码 为 -4 表示 API 查询次数已达上限
                elif r_json['response_code'] == -4:
                    pass
                else:
                    console.log(f"[red][EROR] 微步 API 请求失败，错误信息：{r_json['verbose_msg']}[/red]")
                    return table, ['N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A']

            except Exception:
                console.log(f"[red][EROR] 查询 {ip} 的微步信息程序发生错误，错误信息：{traceback.format_exc()}[/red]")
                return table, ['N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A']
    console.log("[red][ERRO] 微步 API 所有 key 已使用完毕！微步信息查询失败。[/red]")
