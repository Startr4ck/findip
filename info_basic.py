'''
该文件当中存放域名的相关信息的函数

iscdn
没有www的网页的domain请求
历史的IP信息查询
返回请求的响应长度
'''
yellow = '\033[01;33m'
white = '\033[01;37m'
green = '\033[01;32m'
blue = '\033[01;34m'
red = '\033[1;31m'
end = '\033[0m'





import dns.resolver
import requests
import sys
def domain_handler(domain):
    if "http" not in domain or "www" not in domain:
        print("格式不规范 标准格式 http://www.example.com")
        sys.exit(0)
    return domain
def domain_short(domain):
    domain=domain.lstrip("http://www.")
    domain=domain.lstrip("https://www.")
    return  domain
def iscdn(domain,ip_lis,port=80):
    '''
    通过访问dns进行解析出来a记录然后进行访问常见的端口
    :param domain: domain 的形式 example.com
    :param ip_lis: 出现解析a记录的ip的列表
    :param port: 端口默认为80和443
    :return: 判断该域名是否是采用了cdn加速
    '''
    ans = dns.resolver.query(domain,'A')
    for i in ans.response.answer[-1].items:
        ip_lis.append(i.address)
    flag=0
    for ip in ip_lis:
        try:
            r=requests.get('http://'+ip+":"+str(port),timeout=2)
            code=r.status_code
        except:
            code=600
        try:
            r1 = requests.get('https://' + ip + ":443", timeout=2)
            code1 = r1.status_code
        except:
            code1=500

        if code< 400 or code1 <400 :  #表示能够访问其中的IP地址
            flag=1
            break
    if flag:
        print(f'''{red}domain+"不存在cdn 加速"''')
        return True
    else:
        print(f'''{green}domain+"存在cdn 加速"''')
        return False
from urllib.parse import urlparse
def withoutwww(domain,ip_lis):
    '''
    :param domain: domain www.example.com
    :param ip_lis: 输入的ip_lis
    :return: 返回的列表当中加上没有www的域名
    '''

    #除去domain当中的www

    domain=domain.lstrip('www.')
    ans = dns.resolver.query(domain,'A') #还是通过dns进行查询
    if ans:
        for i in ans.response.answer[-1].items:
            if i.address in ip_lis:
                continue
            print(f'''{green}Find a host without www{str(i.address)}''')
            ip_lis.append(i.address)

    return (ip_lis)
import config
import json
def history_ip(domain):
    '''
    :param ip_lis: 输入的IP信息
    :param domain:进行请求的domain的信息 example.com
    :return: 返回的数据还是操作的ip列表
    '''
    url = "https://api.securitytrails.com/v1/history/"+domain+"/dns/a"
    headers = {'accept': 'application/json',
               'APIKEY': config.securitytrail_key
               }
    raw_data = requests.request("GET", url, headers=headers)
    raw_data = json.loads(raw_data.text)
    t=0
    ip_lis=[]
    for i in (raw_data["records"]):
        for j in (i['values']):
            t+=1
            ip_lis.append(j['ip'])
    print(f'''{green}History get {str(t)} ip ''')
    return (list(set(ip_lis)))

def get_resp_len(url):
    #返回数据的响应包信息
    '''
    Get the length of response body.
    '''
    res =999999
    try:
        r = requests.get(url, timeout=2)
        if r.status_code ==200:
            res = len(r.content)
    except:
        pass
    return res