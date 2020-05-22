from mitmproxy import ctx
from mitmproxy import http
import re
import datetime
import json

def request(flow):
    # 过滤后缀名
    black_ext = "css,flv,mp3,mp4,swf,js,jpg,jpeg,png,css,gif,txt,ico,pdf,css3,txt,rar,zip,mkv,avi,mp4,swf,wmv,exe,msi,mpeg,ppt,pptx,doc,docx,xls,xlsx,woff2,woff,map,svg,ttf,m3u8,webp,tiff,bmp,7z,tgz,tar,bz,tbz,gz,apk,ipa"
    global url
    #只对vulstudy.com域名进行信息提取
    flow.request.headers[
        'User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Safari/537.36"
    # 只对主机名为vulstudy.com的数据包进行操作
    if flow.request.host == "vulstudy.com":
        for ext in black_ext.split(","):
            if flow.request.url.lower().endswith("." + ext):
                return
        url = flow.request.url
        print("originl request id", flow.id)
        if flow.request.is_replay:
            create_request_data(flow,"modify_request.txt")
            return
        flow = flow.copy()
        # 将请求包保存为burp日志格式，利用sqlmap可对该日志进行SQL注入扫描
        create_request_data(flow,"original_request.txt")
        flow.request.headers.__delitem__('Cookie')
        if flow.request.method == "POST":
            print("****************************************")
            json_content = json.loads(str(flow.request.content, encoding="utf-8"))
            # 将请求体中的tickets删除
            json_content.pop("tickets")
            byte_content = bytes(json.dumps(json_content), encoding="utf-8")
            print(byte_content)
            flow.request.content = byte_content
            print("****************************************")
        ctx.master.commands.call("replay.client", [flow])  # 重发 函数
        print("modifyed request id", flow.id)


def response(flow: http.HTTPFlow) -> None:
    global original_body, modify_body
    # print("content",flow.response.content)
    if not flow.request.is_replay:
        print("original response id", str(flow.id))
        original_body = len(str(flow.response.text))
        # print(flow.request.headers)
        return
    print("modifyed response id", str(flow.id))
    modify_body = len(str(flow.response.text))
    # 当original_body与modify_body的长度相同时，判断为越权，加一个响应头（仅供参考，需人工判断）
    if original_body == modify_body:
        print(url,'此接口可能存在越权')
        with open('yuequan.txt','a',encoding='utf-8') as ff:
            str1 = "\n"+url+","+str(original_body)+","+str(modify_body)
            ff.write(str(str1))
            ff.close()
    else:
        flow.response.headers["mitmproxy"] = "No"
    print(original_body, modify_body, url)


def create_request_data(flow: http.HTTPFlow,requestTxt):
    str1 = "=" * 54
    dateArray = datetime.datetime.fromtimestamp(flow.request.timestamp_start)
    otherTime = dateArray.strftime("%H:%M:%S")
    http_port = flow.request.port
    http_protocol = flow.request.scheme
    server_ip = "192.168.2.18"  # flow.server_conn.ip_address[0]
    http_path = flow.request.path
    http_method = flow.request.method
    http_version = flow.request.http_version
    mpv = str(http_method) + ' ' + str(http_path) + ' ' + str(http_version)
    fp = flow.request.headers
    headers = [item + ':' + fp[item] for item in fp]
    header = [str(i) + '\n' for i in headers]
    http_headers = ''.join(header)
    http_content = str(mpv) + "\n" + str(http_headers)
    txt = otherTime + "  " + http_protocol + "://" + flow.request.host + ":" + str(http_port) + "  " + "[" + str(
        server_ip) + "]" + "\n"
    if flow.request.method == "GET":
        txt = str1 + "\n" + txt + str1 + "\n" + http_content + "\n" + "\n" + str1 + "\n" * 4
        # ctx.log.info(txt)
    if flow.request.method == "POST":
        post_data = flow.request.content
        try:
            post_data = (str(post_data, encoding='utf-8'))
        except Exception as e:
            post_data = (''.join([chr(int(a)) for a in post_data]))
        txt = str1 + "\n" + txt + str1 + "\n" + http_content + "\n" + post_data + "\n" + str1 + "\n" * 4
        # ctx.log.info(txt)
    with open(requestTxt, "a", encoding="utf-8") as ff:
        ff.write(txt)
        ff.close()

