#  整体思路，请求的的流指向mitmproxy
#   MitmproxySqlmap.py  
将mitmproxy将流量按照burp的日志导出来，使用sqlmap进行批量扫描
```
sqlmap -l sql.txt --batch -smart --force-ssl --proxy=http://192.168.45.100:8080
```
也可利用burp直接导出日志，然后利用sqlmap批量扫描（数据包中有中文时会出错），
可参考```https://blog.csdn.net/hacker234/article/details/105232786```

# unauthorizedAccess.py 
将mitmproxy将流量拦截，删除数据包中的认证，对比两者的返回数据判断是否存在未授权


