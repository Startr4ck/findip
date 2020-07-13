# import base64
# def samecer(domain):
#     import json
#     # from scan import cert2iplis
#     # q3=queue.Queue(100)
#     # def rocksamecer(domain):
#     import config
#     import censys
#     import censys.certificates
#     domain = domain.lstrip('www.')
#     hash = base64.b64encode(domain.encode("utf-8")).decode("utf-8")
#     # import gevent
#     # from gevent import monkey
#     # monkey.patch_all()
#     UID = config.censys_uid
#     SECRET = config.censys_secret
#     ip_lis = []
#     certificates = censys.certificates.CensysCertificates(UID, SECRET)
#     cert_lis = []
#     fields = ["parsed.fingerprint_sha256"]
#     query_str = "parsed.names: " + domain + " and tags.raw: trusted"
#     for c in certificates.search(query_str, fields=fields):
#         cert_lis.append(c["parsed.fingerprint_sha256"])
    # print(cert_lis)
    #
    # for cert in cert_lis:
    #     cert2iplis(cert)
    #
    # print(ip_lis)

# samecer("www.4399.com")

cert_lis = ['59367a6f0ee211ef038fc366562208964a8633fbd5333bb7bdfdfafb1658df4f',
            'badf9cca0f5579369b7bc6bfa81f7e48983fa90733808180d3141b23a67a90f5',
            'c24dfe03a807ceea55e6bb067da7cadcdc438ded8db3eb9127da6a6cd9d6af4b',
            '8d2cff6fbce6182d0ff465d55242184689e4c7590e91c93c6e7b4bb9878edf8f',
            '473c071d1247086b294bdc7d8228825d2e76694cfded589e5617548d2a83a45f',
            'f8e9b81a31d3e9f20892288c4215eaec09497cd4f4c2230051bf4d4f55260b3b',
            '64833459b5d8f8dac6d32fb686615a839e52b525b3c990323284e0c9f9b816bd']


def cert2iplis(cert):
    import config
    import censys.certificates
    query_str=cert
    UID = config.censys_uid
    SECRET = config.censys_secret
    certificates = censys.certificates.CensysCertificates(UID, SECRET)
    for result in certificates.search(query_str):
        print(result)

for cert in cert_lis:
    print(cert2iplis(cert))