import json
try:
    f= open("config.txt")
    res=f.read()
    # print(res)
    # print(type(res))
    json_res=json.loads(res)
    shodan_api = json_res['shodan_api']
    securitytrail_key = json_res['securitytrail_key']
    censys_uid = json_res['censys_uid']
    censys_secret = json_res['censys_secret']
except:
    pass




