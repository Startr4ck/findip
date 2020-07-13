from config import shodan_api


def get_resp_len(url):
    res = 0
    try:
        import requests
        #返回数据的响应包信息
        '''
        Get the length of response body.
        '''


        r = requests.get(url,timeout=3)
        if r.status_code <400:
            res = len(r.content)
    except:
       pass

    return res



from concurrent.futures import ThreadPoolExecutor,ALL_COMPLETED,wait
from queue import Queue
import threading
def simple_task(self,domain,ip_lis):
    q = Queue(50)
    pool=ThreadPoolExecutor()
    len_target=get_resp_len(domain)

    self.all = 0
    self.done = 0
    self.find = 0

    self.all=len(ip_lis)
    print("Here is "+str(self.all))
    lock = threading.Lock()
    all_tasks=[pool.submit(pipei,self,len_target,lock,"http://"+url) for url in ip_lis]

    # res=[]
    # try:
    #     while not q.empty():
    #         res.append(q.get())
    # except:
    #     pass



def pipei(self,lens,lock,ip):

    print("do not taken ")
    if get_resp_len(ip)==lens:
        self.ms.text_print.emit(self.resulttext, ip)
        # print("have found")
        self.ms.to_sign.emit("find") #如果进入了这个步骤则会导致之后的代码不被执行


    # print("done have token")
    self.ms.to_sign.emit("done")



