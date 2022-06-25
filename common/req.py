import traceback
import requests
from rich.console import Console

console = Console()


def req(url, headers, params=None, proxies=None):
    """
    请求 url，判断 url 是否请求成功
    :param url:         string      请求 url
    :param headers:     dict        请求头
    :param params:      string      请求参数
    :param proxies:     dict        代理
    :return:            bool        请求体 r or False
    """
    try:
        r = requests.get(url, headers=headers, params=params, proxies=proxies, timeout=(50, 60),verify=False)
        if r.status_code == 200:
            return r
        else:
            console.log(f"[red][ERROR] {url} 请求失败，http 状态码：{r.status_code} {r.reason} 响应体：{r.text}[/red]")
            return False
    except requests.exceptions.ConnectTimeout:
        console.log(f"[red][EROR] 连接 {url} 超时 [/red]")
        return False
    except requests.exceptions.ProxyError:
        console.log(f"[red][EROR] 连接 {url} 代理失败 [/red]")
        return False
    except Exception:
        console.log(f"[red][EROR] 访问 {url} 发生程序错误，错误信息：{traceback.format_exc()}[/red]")
        return False
