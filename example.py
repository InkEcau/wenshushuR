from wssr import WssR

if __name__ == '__main__':
    # upload
    print(WssR(path='filepath', type=WssR.TaskType.UPLOAD).run())
    
    # download
    print(WssR(path='', type=WssR.TaskType.DOWNLOAD, url='url').run())