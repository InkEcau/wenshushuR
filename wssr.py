import base64
import concurrent.futures
import hashlib
import json
import os
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
import base58
import requests
from Cryptodome.Cipher import DES
from Cryptodome.Util import Padding

from loguru import logger

class WssR():
    CHUNK_SIZE = 2097152
    class TaskType(Enum):
        UPLOAD = 0,
        DOWNLOAD = 1

    def __init__(self, path:str, type:TaskType=TaskType.UPLOAD, url:str=None):
        self.done = False
        self.type = type
        if type == WssR.TaskType.UPLOAD:
            if not os.path.isfile(path): 
                logger.error('文件路径错误')
                raise OSError('Illegal path exception: ' + path)
        elif type == WssR.TaskType.DOWNLOAD:
            if not os.path.isdir(path): 
                logger.error('保存路径错误')
                raise OSError('Illegal path exception: ' + path)
            if url == None:
                logger.error('任务类型WssR.TaskType.DOWNLOAD需要url')
                raise Exception('Param "url" should not be None when WssR task type is WssR.TaskType.DOWNLOAD ')
            self.url = url
        self.path = path.replace('\\', '/')
    
    def run(self):
        self.session = requests.Session()
        r = self.session.post(
            url='https://www.wenshushu.cn/ap/login/anonymous',
            json={
                "dev_info": "{}"
            }
        )
        self.session.headers['X-TOKEN'] = r.json()['data']['token']
        self.session.headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0"
        self.session.headers['Accept-Language'] = "en-US, en;q=0.9"  # NOTE: require header, otherwise return {"code":-1, ...}
        if self.type == WssR.TaskType.UPLOAD:
            self.public_url = self.__upload()
            self.done = True
            return self.public_url
        elif self.type == WssR.TaskType.DOWNLOAD:
            return self.__download()
    
    def __calc_file_hash(self, hashtype, block=None, chunk_size=CHUNK_SIZE, ispart=True):
        read_size = chunk_size if ispart else None
        if not block:
            with open(self.path, 'rb') as f:
                block = f.read(read_size)
        if hashtype == "MD5":
            hash_code = hashlib.md5(block).hexdigest()
        elif hashtype == "SHA1":
            hash_code = hashlib.sha1(block).hexdigest()
        return hash_code

    def __read_file(self, block_size):
        partnu = 0
        with open(self.path, "rb") as f:
            while True:
                block = f.read(block_size)
                partnu += 1
                if block:
                    yield block, partnu
                else:
                    return
    
    def __file_put(self, ispart, fname, file_size, upId, partnu, fn, read_size=CHUNK_SIZE, offset=0):
        with open(fn, "rb") as fio:
            fio.seek(offset)
            payload = {
                "ispart": ispart,
                "fname": fname,
                "fsize": file_size,
                "upId": upId,
            }
            if ispart:
                payload["partnu"] = partnu
            r = self.session.post(
                url="https://www.wenshushu.cn/ap/uploadv2/psurl",
                json=payload
            )
            rsp = r.json()
            url = rsp["data"]["url"]  # url expires in 600s (10 minutes)
            requests.put(url=url, data=fio.read(read_size))


    def __upload(self):

        file_size = os.path.getsize(self.path)
        ispart = True if file_size > WssR.CHUNK_SIZE else False

        ## addsend
        # userinfo
        self.session.post(
            url='https://www.wenshushu.cn/ap/user/userinfo',
            json={"plat": "pcweb"}
        )

        # storage
        r = self.session.post(
            url='https://www.wenshushu.cn/ap/user/storage',
            json={}
        )
        rsp = r.json()
        rest_space = int(rsp['data']['rest_space'])
        send_space = int(rsp['data']['send_space'])
        storage_space = rest_space + send_space
        logger.info('当前已用空间:{}GB,剩余空间:{}GB,总空间:{}GB'.format(
            round(send_space / 1024**3, 2),
            round(rest_space / 1024**3, 2),
            round(storage_space / 1024**3, 2)
        ))

        # get_epochtime
        r = self.session.get(
            url='https://www.wenshushu.cn/ag/time',
            headers={
                "Prod": "com.wenshushu.web.pc",
                "Referer": "https://www.wenshushu.cn/"
            }
        )
        epochtime = r.json()["data"]["time"]

        req_data = {
            "sender": "",
            "remark": "",
            "isextension": False,
            "notSaveTo": False,
            "notDownload": False,
            "notPreview": False,
            "downPreCountLimit": 0,
            "trafficStatus": 0,
            "pwd": "",
            "expire": "1",
            "recvs": [
                "social",
                "public"
            ],
            "file_size": file_size,
            "file_count": 1
        }
        
        # POST的内容在服务端会以字串形式接受然后直接拼接X-TOKEN，不会先反序列化JSON字串再拼接
        # 加密函数中的JSON序列化与此处的JSON序列化的字串形式两者必须完全一致，否则校验失败
        
        # get_cipherheader
        # cipherMethod: DES/CBC/PKCS7Padding
        json_dumps = json.dumps(req_data, ensure_ascii=False)
        md5_hash_code = hashlib.md5((json_dumps+self.session.headers['X-TOKEN']).encode()).hexdigest()
        base58_hash_code = base58.b58encode(md5_hash_code)
        key_iv = (
            # 时间戳逆序取5位并作为时间戳字串索引再次取值，最后拼接"000"
            "".join([epochtime[int(i)] for i in epochtime[::-1][:5]]) + "000"
        ).encode()
        cipher = DES.new(key_iv, DES.MODE_CBC, key_iv)
        cipherText = cipher.encrypt(
            Padding.pad(base58_hash_code, DES.block_size, style="pkcs7")
        )
        a_code = base64.b64encode(cipherText)

        r = self.session.post(
            url='https://www.wenshushu.cn/ap/task/addsend',
            json=req_data,
            headers={
                "A-code": a_code,
                "Prod": "com.wenshushu.web.pc",
                "Referer": "https://www.wenshushu.cn/",
                "Origin": "https://www.wenshushu.cn",
                "Req-Time": epochtime,
            }
        )
        rsp = r.json()
        if rsp["code"] == 1021:
            logger.error(f'操作太快啦！请{rsp["message"]}秒后重试')
            raise Exception('API error: operation too fast')
        data = rsp["data"]
        if not data:
            logger.error('需要滑动验证码')
            raise Exception('API error: authenticator code required')
        boxid, preid, taskid = data["bid"], data["ufileid"], data["tid"]
        r = self.session.post(
            url="https://www.wenshushu.cn/ap/uploadv2/getupid",
            json={
                "preid": preid,
                "boxid": boxid,
                "linkid": taskid,
                "utype": "sendcopy",
                "originUpid": "",
                "length": file_size,
                "count": 1
            }
        )
        upId = r.json()["data"]["upId"]
        cm1, cs1 = self.__calc_file_hash("MD5", ispart=ispart), self.__calc_file_hash("SHA1", ispart=ispart)
        cm = hashlib.sha1(cm1.encode()).hexdigest()
        name = os.path.basename(self.path)
        payload = {
            "hash": {
                "cm1": cm1,  # MD5
                "cs1": cs1,  # SHA1
            },
            "uf": {
                "name": name,
                "boxid": boxid,
                "preid": preid
            },
            "upId": upId
        }

        if not ispart:
            payload['hash']['cm'] = cm  # 把MD5用SHA1加密
        for _ in range(2):
            r = self.session.post(
                url='https://www.wenshushu.cn/ap/uploadv2/fast',
                json=payload
            )
            rsp = r.json()
            can_fast = rsp["data"]["status"]
            ufile = rsp['data']['ufile']
            if can_fast and not ufile:
                hash_codes = ''
                for block, _ in self.__read_file(block_size=WssR.CHUNK_SIZE):
                    hash_codes += self.__calc_file_hash("MD5", block=block, ispart=ispart)
                payload['hash']['cm'] = hashlib.sha1(hash_codes.encode()).hexdigest()
            elif can_fast and ufile:
                logger.info(f'文件{name}可以被秒传！')
                # getprocess
                while True:
                    r = self.session.post(
                        url="https://www.wenshushu.cn/ap/ufile/getprocess",
                        json={
                            "processId": upId
                        }
                    )
                    if r.json()["data"]["rst"] == "success":
                        break
                    time.sleep(1)
                # copysend
                r = self.session.post(
                    url='https://www.wenshushu.cn/ap/task/copysend',
                        json={
                            'bid': boxid,
                            'tid': taskid,
                            'ufileid': preid
                        }
                )
                rsp = r.json()
                logger.success(f"个人管理链接：{rsp['data']['mgr_url']}")
                logger.success(f"公共链接：{rsp['data']['public_url']}")
                return rsp['data']['public_url']
            
        if ispart:
            logger.info('文件正在被分块上传！')
            with ThreadPoolExecutor(max_workers=4) as executor:  # or use os.cpu_count()
                future_list = []
                for i in range((file_size + WssR.CHUNK_SIZE - 1)//WssR.CHUNK_SIZE):
                    ul_size = WssR.CHUNK_SIZE if WssR.CHUNK_SIZE*(i+1) <= file_size \
                        else file_size % WssR.CHUNK_SIZE
                    future_list.append(executor.submit(
                        self.__file_put, ispart=ispart, fname=name, file_size=ul_size, upId=upId, partnu=i+1, fn=self.path, read_size=ul_size, offset=WssR.CHUNK_SIZE*i
                    ))
                future_length = len(future_list)
                count = 0
                for _ in concurrent.futures.as_completed(future_list):
                    count += 1
                    sp = count / future_length * 100
                    logger.info(f'分块进度:{int(sp)}%')
                    if sp == 100:
                        logger.info('上传完成:100%')
        else:
            logger.info('文件被整块上传！')
            self.__file_put(ispart=ispart, fname=name, file_size=file_size, upId=upId, partnu=None, fn=self.path, read_size=file_size, offset=0)
            logger.info('上传完成:100%')
        
        self.session.post(
            url="https://www.wenshushu.cn/ap/uploadv2/complete",
            json={
                "ispart": ispart,
                "fname": name,
                "upId": upId,
                "location": {
                    "boxid": boxid,
                    "preid": preid
                }
            }
        )
        r = self.session.post(
            url='https://www.wenshushu.cn/ap/task/copysend',
            json={
                'bid': boxid,
                'tid': taskid,
                'ufileid': preid
            }
        )
        rsp = r.json()
        logger.info(f"个人管理链接：{rsp['data']['mgr_url']}")
        logger.info(f"公共链接：{rsp['data']['public_url']}")
        while True:
            r = self.session.post(
                url="https://www.wenshushu.cn/ap/ufile/getprocess",
                json={
                    "processId": upId
                }
            )
            if r.json()["data"]["rst"] == "success":
                break
            time.sleep(1)
        return rsp['data']['public_url']

    def __download(self):
        # 个人管理链接
        if len(self.url.split('/')[-1]) == 16:
            token = self.url.split('/')[-1]
            r = self.session.post(
                url='https://www.wenshushu.cn/ap/task/token',
                json={
                    'token': token
                }
            )
            tid = r.json()['data']['tid']
        # 公共链接
        elif len(self.url.split('/')[-1]) == 11:
            tid = self.url.split('/')[-1]

        # mgrtask
        r = self.session.post(
            url='https://www.wenshushu.cn/ap/task/mgrtask',
            json={
                'tid': tid,
                'password': ''
            }
        )
        rsp = r.json()
        expire = rsp['data']['expire']
        days, remainder = divmod(int(float(expire)), 3600*24)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        logger.info(f'文件过期时间:{days}天{hours}时{minutes}分{seconds}秒')

        file_size = rsp['data']['file_size']
        logger.info(f'文件大小:{round(int(file_size)/1024**2,2)}MB')
        bid = rsp['data']['boxid']
        pid = rsp['data']['ufileid']

        # list_file
        r = self.session.post(
            url='https://www.wenshushu.cn/ap/ufile/list',
            json={
                "start": 0,
                "sort": {
                    "name": "asc"
                },
                "bid": bid,
                "pid": pid,
                "type": 1,
                "options": {
                    "uploader": "true"
                },
                "size": 50
            }
        )
        rsp = r.json()
        filename = rsp['data']['fileList'][0]['fname']
        fid = rsp['data']['fileList'][0]['fid']
        logger.info(f'文件名:{filename}')

        # sign
        r = self.session.post(
            url='https://www.wenshushu.cn/ap/dl/sign',
            json={
                'consumeCode': 0,
                'type': 1,
                'ufileid': fid
            }
        )
        if r.json()['data']['url'] == "" and r.json()['data']['ttNeed'] != 0:
            logger.error("对方的分享流量不足")
            return None
        url = r.json()['data']['url']
        logger.info('开始下载!', end='\r')
        r = self.session.get(url, stream=True)
        dl_size = int(r.headers.get('Content-Length'))
        dl_count = 0
        fp = (self.path if self.path.endswith('/') else self.path + '/') + filename
        with open(fp, 'wb') as f:
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=WssR.CHUNK_SIZE):
                f.write(chunk)
                dl_count += len(chunk)
                logger.info(f'下载进度:{int(dl_count/dl_size*100)}%')
            logger.success(f'下载完成, 存储至{fp}')
            self.done = True
            return fp

if __name__ == '__main__':
    try:
        command = sys.argv[1]
        if command.lower() in ['upload', 'u']:
            file = sys.argv[2]
            WssR(file, type=WssR.TaskType.UPLOAD).run()
        elif command.lower() in ['download', 'd']:
            url = sys.argv[2]
            WssR(path='', type=WssR.TaskType.DOWNLOAD, url=url).run()
    except IndexError:
        logger.warning('请输入正确命令\n',
              '上传:[python wssr.py upload <上传文件路径>]\n',
              '下载:[python wssr.py download <文件分享链接>]')
    except Exception as e:
        traceback.print_exc()