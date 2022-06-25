# DEV 修改版本

<https://github.com/Mr-mocun/Threat_Intelligence_View/tree/dev>

# Updata

## 更新时间：2022 年 06 月 25 日

### 1. 功能优化

1. 添加了 Nsfocus 威胁情报解析结果，但 API 需要自行获取；

2. 优化了配置文件，支持添加多个微步 API key，第一个到达上限后，继续读取下一个，突破了微步 API 每日 50 次的限制；

3. 优化了配置文件，通过对 `Nsfocus_enable`、`FOFA_enable` 、`Revrse_IP_Lookup_enable` 使能开关控制，自定义调整查询结果。

4. 删除通过请求 [api.hackertarget.com](https://api.hackertarget.com/reverseiplookup/?q=x.x.x.x) 来获取 ip 反查域名，由于请求次数每日免费仅 10 次，因此删除该链接；

5. 删除 IP 存活判断。通过 ping 来判断 IP 存活的方式，可靠性不高，因此删除函数调用，但保留了该部分函数；

6. Fofa 官网地址修改，修改了 `fofa` api 获取地址描述，修改了 `fofa` api 接口地址请求；

7. 默认查询单一 IP 不保存文件。实际使用中发现查询单一 ip 威胁情报保存文件的情况并不多，因此修改为默认不保存，但可以通过指定保存文件名的方式来强制保存，示例 `python3 tiv.py -i x.x.x.x -o yyyy(.xlsx)`； `yyyy` 为文件名，后缀名可加可不加；

8. 修改批量查询 IP 读取文件内容筛选 ip 的方式，可以无需按照一行一个 ip 的格式进行书写。可随意书写，通过正则方式匹配 `x.x.x.x` 的格式筛选 ip。

9. 修改批量查询 ip 默认保存输出文件名，不再以时间戳方式保存，修改为年月日时分秒+ip 个数的方式保存；如 `tiv_2022 年 06 月 25 日_16 时 09 分 25 秒_2 个 IP.xlsx`。

10. 重构代码逻辑，按照 PEP8 规范优化部分书写方式，添加注释，函数说明，返回正确值 demo，错误值 demo。

### 2. bug 修复

1. 修改了 ip 反查域名时，若包含多个域名列表时，域名信息（备案信息，注册人，注册商等）仅保存最后一个域名信息。域名相关信息保存至 sheet2（域名信息）中。

2. 修复其他报错情况（如 json 解析异常，whois 返回值未考虑数组等问题），优化进度条被打断等问题。

**fork from：**

        https://github.com/wgpsec/tig
