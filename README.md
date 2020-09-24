## 获取目标机器的微信数据库和密钥

前段时间在网上看文章，看到一篇微信解密数据库的文章，然后突然有了想法，如果有一个类似后门的程序，在女友的电脑上运行后（无中生友）把时刻的聊天记录发过来，岂不是可以实时监控我头顶的帽子颜色。。。。

然后就去搜了文章和视频，主要学了关于微信逆向的各种操作，对微信的各个功能模块和行为流程有了初步的认识。

## 需要
https://slproweb.com/download/Win32OpenSSL-1_0_2u.exe

openssl 解密脚本用了网上师傅的老脚本，需要用老版本的openssl

## 系统功能和流程

![](https://raw.githubusercontent.com/A2kaid/Get-WeChat-DB/master/model.png)

## 版本
v1.0

udp传输，微信版本为 v2.9.0.123

v2.0

udp丢包严重，换成了tcp，这下nc也可以接收了，微信版本为 v2.9.5.56
每次更新密钥，wxid的基址会变，正在想方法自动化获取基址。

## 参考文章和项目

- https://blog.csdn.net/qq_38474570/article/details/96606530
  PC微信逆向：两种姿势教你解密数据库文件
-   https://github.com/zzyzhangziyu/wechat-db-decrypt
  解密Windows微信聊天记录数据库
-   https://github.com/cdjjustin/UDP
  UDP大文件传输 
-   https://www.52pojie.cn/thread-1084703-1-1.html
  PC微信逆向分析の绕过加密访问SQLite数据库
