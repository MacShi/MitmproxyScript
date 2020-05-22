import mitmproxy.http
from mitmproxy import ctx, http
import mitmproxy.http
from mitmproxy import ctx
import datetime


def request(flow: mitmproxy.http.HTTPFlow):
    black_ext = "css,flv,mp3,mp4,swf,js,jpg,jpeg,png,css,gif,txt,ico,pdf,css3,txt,rar,zip,mkv,avi,mp4,swf,wmv,exe,msi,mpeg,ppt,pptx,doc,docx,xls,xlsx,woff2,woff,map,svg,ttf,m3u8,webp,tiff,bmp,7z,tgz,tar,bz,tbz,gz,apk,ipa"
    str1 = "=" * 54
    dateArray = datetime.datetime.fromtimestamp(flow.request.timestamp_start)
    otherTime = dateArray.strftime("%H:%M:%S")
    if flow.request.host == "XXXXXX.com":
        for ext in black_ext.split(","):
            if flow.request.url.lower().endswith("." + ext):
                return
        http_port = flow.request.port
        http_protocol = flow.request.scheme
        server_ip = flow.server_conn.ip_address[0]
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
            ctx.log.info(txt)
        if flow.request.method == "POST":
            post_data = flow.request.content
            try:
                post_data = (str(post_data, encoding='utf-8'))
            except Exception as e:
                post_data = (''.join([chr(int(a)) for a in post_data]))
            txt = str1 + "\n" + txt + str1 + "\n" + http_content + "\n" + post_data + "\n" + str1 + "\n" * 4
            ctx.log.info(txt)
        with open("aa.txt", "a", encoding="utf-8") as ff:
            ff.write(txt)
            ff.close()
