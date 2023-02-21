<h1 align="center">- wenshushuR （文叔叔） -</h1>
<p align="center"> Python 3.7 </p>
<p align="center"> 多线程上传下载，秒传，使用体验与网页无差别。 </p>
<p align="center"> 本fork在原作基础上稍作改动。 </p>
<p align="center"> 文叔叔是良心网站，<strong>请勿滥用 </strong></p>

## 改动

- 使用`loguru`库作日志输出
- 将原作封装，便于调用

## 命令行使用教程

#### 1. 安装依赖

```shell
pip install requests base58 pycryptodomex loguru
```

#### 2. 上传

```shell
python wssr.py upload <上传文件路径>
```

#### 3. 下载

```shell
python wssr.py download <分享链接>
```

#### 4. 返回

管理链接可以用来销毁文件，分享文件，续期文件。

公共链接只能用于下载。

## 调用示例

```python
from wssr import WssR

if __name__ == '__main__':
    # upload
    print(WssR(path='filepath', type=WssR.TaskType.UPLOAD).run())
    
    # download
    print(WssR(path='', type=WssR.TaskType.DOWNLOAD, url='url').run())
```

### 注意事项

1. 在 Windows 下使用时，文件名如果为 " .\xxx" ，那么上传的是一个文件夹，文件夹里面是这个文件，所以如果上传文件的话，路径的斜杠需要为 “ / " 。
2. 由于游客并不能查看自己上传过的文件，所以每次上传均会生成一个新的 **X-TOKEN**。
