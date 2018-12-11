1)haproxy在线维护
1.1)在haproxy中添加
stats socket /var/run/haproxy.sock level admin
（这里的admin是登录haproxy状态页的用户)
1.2)安装socat
yum -y install socat

1.3)查看help帮助
[root@testserver conf]# echo "help" | socat stdio /var/run/haproxy.sock 

1.4)停止某台后端服务器
[root@testserver conf]# echo "disable server backend_www_c_com/node01"|socat stdio /var/run/haproxy.sock 

1.5)启用某台后端服务器
[root@testserver conf]# echo "enable server backend_www_c_com/node01"|socat stdio /var/run/haproxy.sock


2）haproxy官网文档
   http://cbonte.github.io/haproxy-dconv/

3）
  主程序： /data/app/haproxy/sbin/haproxy

  配置文件： /data/app/haproxy/conf/haproxy.cfg



一）haproxy介绍
1、haproxy性能
单进程、事件驱动模型
0（1）事件检查器
单缓冲机制能以不复制任何数据的方式完成读写操作，节省大量的cpu时钟周期及内存带宽
零复制转发、零复制启动
即使内存分配
弹性二叉树



二）配置文件

全局配置段参数详解

1.1)定义日志，最多可以定义两个
log <address> <facility> <level>

常见的日志级别：
emerg  alert  crit   err    warning notice info  debug

1.2）定义每用户（每进程)所能够打开的文件句柄数

ulimit-n <number>

1.3) 让haproxy以守护进程的方式工作于后台

deamon 

1.4) 指定运行haproxy进程的用户和组
group <group name>

user <user name>

1.5) 指定进程的pid文件
pidfile <pidfile>

1.6）用户访问统计数据的接口
stats socket [<address:port>|<path>] [param*]

socat命令

1.7）设定每个haproxy进程所接受的最大并发连接数
maxconn <number>

1.8) 在haproxy后端有着众多服务器的场景中，在精确的时间间隔后统一对众服务器进行健康状况检查可能会带来意外问题；此选项用于将其检查的时间间隔长度上增加或减小一定的随机时长
spread-checks <0..50, in percent>



二）代理段配置

Proxy configuration can be located in a set of sections :
 - defaults [<name>]
 - frontend <name>
 - backend  <name>
 - listen   <name>

defaults配置段（作用：用于为所有其它配置段提供默认参数）
frontend前端配置（作用：定义一系列监听的套接字）
backend后端配置（作用：定义一系列“后端”服务器）
listen（作用：关联“frontend”和“backend”，一般很少用）

1、bind参数

bind [<address>]:<port_range> [, ...] [param*]

范围：frontend、listen

案例：

listen http_proxy
    bind :80,:443
    bind 10.0.0.1:10080,10.0.0.1:10443
    bind /var/run/ssl-frontend.sock user root mode 600 accept-proxy

frontend frontend_www_c_com
  bind *:80


2、balance 后端服务器组内服务器的调度算法

balance <algorithm> [ <arguments> ]
balance url_param <param> [check_post]

范围： defautls、backend、listen

调度算法：

	roundrobin: 基于权重进行轮询（动态），支持4095个后端，支持慢启动
	static-rr： 基于权重进行轮询（静态），每个后端服务器连接没有限制
    leastconn（WLC）：适用于长连接的会话，新的连接请求被派发至具有最少连接数目的后端服务器
    source：将请求的源地址进行hash运算，并由后端服务器的权重总数相除后派发至某匹配的服务器
    uri：对URI的左半部分(“问题”标记之前的部分)或整个URI进行hash运算，并由服务器的总权重相除后派发至某匹配的服务器
    url_param：对用户请求的uri的<params>部分的参数作为hash计算，并由服务器总权重相除以后派发至某后端服务器
    hdr(<name>)：对于每个HTTP请求，通过<name>指定的HTTP首部将会被检索 如hdr(User_Agent)  hdr(Cookie)

可以使用hash-type修改此特性
	除权取余法
	一致性哈希（/2^32）,影响局部

hash-type <method>
	map-based； 除权取余法（静态的）
	consistent： 一致性哈希（动态的）



3）server 定义后端主机的各类服务器

server <name> <address>[:[port]] [param*]

范围： listen、backend

param参数如下：
3.1）maxconn <num> 当前server的最大并发连接数
3.2) backlog <backlog>当前server的连接数达到上限后的队列长度
3.2）backup 设置当前server为备用服务器
3.3）check 对当前server做健康状态检测
	 addr: 检测使用的ip地址
	 port：检测端口
	 inter <delay> 连续两次检测之间的时间间隔 默认为2000ms
	 rise <count> 连续多少次检测结果为成功才标记为可用，默认为2次
	 fall <count> 连续多少次检测结果为失败才标记为不可用，默认为3次
3.4）cookie <value> 为当前server指定其cookie值，用于实现基于cookie的会话粘性
3.5）disabled 标记为不可用
3.5) redir <prefix> 将发往此server上的所有get和head请求重定向指定的url
3.6）weight <weight> 权重

案例：
server first  10.1.1.1:1080 cookie first  check inter 1000
server second 10.1.1.2:1080 cookie second check inter 1000

cookie SERVERID insert indirect
server node02 192.168.10.162:8080  cookie node02  check inter 2000 rise 3 fall 2
server node01 192.168.10.163:8080  cookie node01  check inter 2000 rise 3 fall 2
server node03 192.168.10.166 backup



5）cookie
语法：
cookie <name> [ rewrite | insert | prefix ] [ indirect ] [ nocache ] [ postonly ] [ preserve ] [ httponly ] [ secure ] [ domain <domain> ]* [ maxidle <idle> ] [ maxlife <life> ] [ dynamic ]

name： 指明cookie的名称（这个cookie被发送到
客户端通过响应中的“Set-Cookie”报头，是
由客户端在所有请求的“Cookie”报头中带回）

方式：
   rewirte： 重写
   insert： 插入（用的最多）
   prefix：前缀

indirect：响应报文中有cookie的名称和值，就直接发送给客户端


注意点：
5.1）如果将配置文件中的cookie名称也设置为PHPSESSID，即后端应用服务器和此处设置的cookie名称相同，那么haproxy将首先将后端的PHPSESSID删除，然后使用自己的值发送给客户端。也就是说，此时将只有一个"Set-Cookie"字段响应给客户端
5.2）如果不配合"indirect"选项，服务端可以看到客户端请求时的所有cookie信息
5.3）当客户端和HAProxy之间存在缓存时，建议将insert配合nocache一起使用
5.4）使用prefix的时候，cookie指令设置的cookie名必须和后端设置的cookie一样(在本文的环境中是PHPSESSID)
案例：
cookie SERVERID insert indirect nocache

6) stats 统计接口

范围：frontend,backend,listen

案例：
listen statistics
  mode http
  bind *:18088
  stats enable
  stats auth admin:admin123
  stats uri /admin?status
  stats hide-version
  stats admin if TRUE
  stats show-node
  acl allow src 192.168.10.0/255.255.255.0
  tcp-request content accept if allow
  tcp-request content reject
  stats realm Haproxy Statistics


. disable a server for maintenance（标记某台服务器处于维护模式）
echo "disable server backend_www_c_com/node01"|socat stdio /var/run/haproxy.sock 
. enable a disabled server
echo "enable server backend_www_c_com/node01"|socat stdio /var/run/haproxy.sock 


7) mode
mode { tcp|http|health }
tcp：实例运行于纯TCP模式，在客户端和服务器端之间将建立一个全双工的连接
http：实例运行于HTTP模式
health：不常用

listen ssh-node01
  mode tcp
  bind 192.168.10.166:2201
  server node01 192.168.10.162:22 check

listen ssh-node02
  mode tcp
  bind 192.168.10.166:2202
  server node01 192.168.10.163:22 check

8）定义错误页

errorfile <code> <file> 

案例：
errorfile 400 /data/app/haproxy/errorfiles/400.http
errorfile 403 /data/app/haproxy/errorfiles/403.http
errorfile 408 /data/app/haproxy/errorfiles/408.http
errorfile 500 /data/app/haproxy/errorfiles/500.http
errorfile 502 /data/app/haproxy/errorfiles/502.http
errorfile 503 /data/app/haproxy/errorfiles/503.http
errorfile 504 /data/app/haproxy/errorfiles/504.http


errorloc <code> <url>

案例：
acl badguy src 10.0.10.1
block if badguy
errorloc 403 http://baidu.com/     #定义错误页面重定向

acl dstipaddrhdr(Host) 10.0.10.61
redirect location  http://www.qq.com/ if dstipaddr
errorloc 403 http://baidu.com

如果头部信息包含此IP地址那么将其重定向至qq.com、如果非此IP地址，那么请求的uri返回是403，那么则直接跳转到baidu.com
9） reqadd <string> [if <cond>]

向请求报文的首部添加值
reqiel <string>
删除请求报文的某个值

(改变的是：haproxy发送请求报文到后端服务器）

rspadd <string> [if <code>]
向响应报文首部添加值

rspidel <string>

（改变的是： haproxy发送响应报文给客户端）
范围：frontend、listen、backend

案例：
rspidel ^Server:.*
acl is-ssl  dst_port       81
reqadd      X-Proto:\ SSL  if is-ssl


10）log

10.1)tcp日志格式
案例：
    frontend fnt
        mode tcp
        option tcplog
        log global
        default_backend bck

    backend bck
        server srv1 127.0.0.1:8000

>>> Feb  6 12:12:56 localhost \
      haproxy[14387]: 10.0.1.2:33313 [06/Feb/2009:12:12:51.443] fnt \
      bck/srv1 0/0/5007 212 -- 0/0/0/0/3 0/0

日志解释：
haproxy[14387]------进程名【进程号】
10.0.1.2:33313-----客户端ip[客户端端口]
[06/Feb/2009:12:12:51.443] --接收日期
fnt-----frontend名称
bck/srv1----backend名称/backend服务器
Tw '/' Tc '/' Tt* 
	- Tw: 队列中等待的时长（总时间） 
	- Tc: 创建连接所消耗的时长
	- Tt: 接收响应报文所消耗的时长
212----------从服务器传输的总字节数
--：termination_state
0/0/0/0/3:
	actconn: 当会话记录到日志，当前进程上的并发连接总数
	feconn:  前端连接总数
	beconn:  后端连接总数
	srv_conn： 是仍处于活动状态的并发连接总数，记录会话时的服务器
	retries: 重试次数
srv_queue'/'backend_queue

10.2）http日志格式
案例：
frontend http-in
        mode http
        option httplog
        log global
        default_backend bck

    backend static
        server srv1 127.0.0.1:8000

>>> Feb  6 12:14:14 localhost \
      haproxy[14389]: 10.0.1.2:33317 [06/Feb/2009:12:14:14.655] http-in \
      static/srv1 10/0/30/69/109 200 2750 - - ---- 1/1/1/1/0 0/0 {1wt.eu} \
      {} "GET /index.html HTTP/1.1"

 10.3)自定义日志格式

 %ci:%cp: 客户端ip:客户端端口
 %si:%sp: 服务端IP：服务端端口
 %B： bytes_read           (from server to client)  
 %U： bytes_uploaded       (from client to server)
 %ST：状态码
 %r:  http请求
%f： 前端名称
%b/%s:  后端名称/后端服务器名称
%hrl： captured_request_headers CLF style 
%hsl： captured_response_headers CLF style

案例：
frontend frontend_www_c_com
  bind *:80
  mode http
  log global
  option forwardfor
  option httplog
  capture request header Host len 64
  capture request header User-Agent len 160
  capture request header X-Forwarded-For len 100
  capture request header Referer len 200
  #capture response header Server len 40
  log-format %ci:%cp\ %si:%sp\ %B\ %U\ %ST\ %r\ %b\%s\ %f\ %hrl\ %hsl\
  default_backend backend_www_c_com


Dec 11 10:56:22 localhost haproxy[19478]: 192.168.10.110:65281 192.168.10.162:8080 252 450 200 GET /test3.html HTTP/1.1 backend_www_c_com\node01 frontend_www_c_com www.c.com Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36 - - \


11）capture捕获

haproxy利用capture捕获请求(request)和响应(response)信息

capture request header <name> len <length>
案例：
capture request header Host len 15
capture request header X-Forwarded-For len 15
capture request header Referer len 15

capture response header <name> len <length>
案例：
capture response header Content-length len 9
capture response header Location len 15

12）为指定的MIME 类型启用压缩传输功能

compression algo <algorithm> ... ：启用http 协议的压缩机制，指明压缩算法gzip, deflate

compression type <mime type> ... ：指明压缩的MIMI 类型 （文本类型html、css、js等）

案例：
compression algo gzip
compression type text/html text/plain

13) 对后端服务器做http协议的监控检查
option httpchk
option httpchk <uri>
option httpchk <method> <uri>
option httpchk <method> <uri> <version>

案例：
option httpchk OPTIONS * HTTP/1.1\r\nHost:\ www.c.com

option httpchk HEAD /test1.html HTTP/1.0


http-check expect [!] <match> <pattern>
pattern：
	 rstring <regex> 
	 rstatus <regex>
	 string <string>
案例
option httpchk GET /test1.html HTTP/1.0
http-check expect rstring .*Test.*


option  dontlognull  
#不记录健康检查日志信息
option redispatch
#当与上游服务器的会话失败(服务器故障或其他原因)时，把会话重新分发到其他健康的服务器上,当原来故障的服务器恢复时，会话又被定向到已恢复的服务器上。还可以用”retries”关键字来设定在判定会话失败时的尝试连接的次数。
retries 3
#向上游服务器尝试连接的最大次数，超过此值就认为后端服务器不可用
option abortonclose
#当haproxy负载很高时，自动结束掉当前队列处理比较久的链接

14) 连接超时

timeout client <timeout> 定义客户端与haproxy连接后，数据传输完毕，不再有数据传输，即非活动连接的超时时间，单位为毫秒 （客户端）
timeout server <timeout> 定义haproxy与上游服务器非活动连接的超时时间。（服务端）
timeout http-keep-alive <timeout> 持久连接的持久时长（客户端）
timeout connect <timeout> haproxy与后端服务器连接超时时间，如果在同一个局域网可设置较小的时间





15）ACL访问控制

ACL语法

acl <aclname> <criterion> [flags] [operator] [<value>] ...

aclname: 指定acl的名称，在引用时区别大小写，且多个acl指令可以指定同一个aclname，表示“或”的关系
criterion： 指定检查标准，即检查方法
flag： 可选项，标志位。一般会用到的-i,不区分大小写、-n禁止dns反解析
operator: 可选项，eq、ge、gt、le、lt
value： 根据criterion的不同，值的类型也不同
	--boolean
	--integer(整数)
	--ip地址
	--string（exact、substring、prefix、domain）
15.1）四层常用的检查标准
src <ip_addr>
src_port <PORT or PORT_ranges>
dst <ip_addr>
dst_port <PORT or PORT_ranges>

案例：
acl accept_clients src 192.168.10.0/24
acl reject_clients src 10.1.10.0/24
tcp_request content accept if accept_clients
tcp_request content  reject if reject_clients

acl invalid_src src 192.168.10.20
block if invalid_src

15.2)7层常用的检查标准

. hdr(HEADER) 检查首部字段是否为指定的模式  
	hdr(Connection) -i close
	hdr(Host) -i www.a.com

. hdr_reg(HEADER) 检查首部字段是否匹配指定的模式
  hdr_reg(Host) -i .*\.51yuki\.com
  hdr_beg(HEADER) 检查首部字段是以匹配的模式开头


  hdr_beg(Host) -i img. video. download. images. videos.

案例：根据不同的浏览器跳转到不同的后端
acl bad_curl hdr_sub(User-Agent) -i curl
use_backend curl if bad_curl
backend curl
   balance roundrobin
   server curl1 192.168.10.165:80 check 
#redirect prefix http://www.a.com/1.html if bad_curl

案例：域名跳转
acl www_c_com hdr_beg(host) -i www.c.com
redirect prefix https://www.91als.com if www_c_com

当访问www.c.com/test3.html就会跳转到https://www.91als.com/test3.html




. method 请求的方法为指定的方法
  acl valid_method method GET
  http-request deny if ! valid_method

 . path_beg: 匹配path的前缀部分
 . path_end: 匹配path的后缀部分

案例：
#定义当请求的内容是静态内容时，将请求转交给static server的acl规则       
acl url_static path_beg  -i /static /images /img /javascript /stylesheets
acl url_static path_end  -i .jpg .gif .png .css .js .html 
acl host_static hdr_beg(host)  -i img. video. download. ftp. imags. videos.
#定义当请求的内容是php内容时，将请求转交给php server的acl规则    
acl url_php path_end     -i .php
#定义当请求的内容是.jsp或.do内容时，将请求转交给tomcat server的acl规则    
acl url_jsp path_end     -i .jsp .do
#引用acl匹配规则
use_backend static_pool if  url_static or host_static
use_backend php_pool    if  url_php
use_backend tomcat_pool if  url_jsp

. url_beg  对url的前缀进行匹配

ACL derivatives :
  url     : exact string match
  url_beg : prefix match
  url_dir : subdir match
  url_dom : domain match
  url_end : suffix match
  url_len : length match
  url_reg : regex match
  url_sub : substring match

ACL derivatives :
  path     : exact string match
  path_beg : prefix match
  path_dir : subdir match
  path_dom : domain match
  path_end : suffix match
  path_len : length match
  path_reg : regex match
  path_sub : substring match


注意：多个条件使用"AND"、"OR"、"!"操作符表示逻辑与、逻辑或和取反，不写时默认的操作符是"AND"。


http-request allow|deny [if <condition>]








16）配置haproxy支持https协议

bind *:443 ssl crt /path/to/some_pem_file(证书文件路径)

crt后的证书文件要求pem格式，且同时包含证书和与之匹配的所有私钥

cat 51yuki.cn.crt 51yuki.cn.key > 51yuki.cn.pem

把80端口的请求重定向到443

bind *.80
redirect scheme https if !{ssl_fc} (该acl不用事先定义)


如何向后端传递用户请求的协议和端口
http_request set-header X-Forwarded-Port %[dst_port]
http_request add-header X-Forwarded-Proto https if {ssl_fc}


17) haproxy重定向应用
redirect指令
(1)位置重定向
redirect location <loc> [code <code>] <option> [{if | unless} <condition>]
使用位置重定向，重定向到所提供的精确位置，该位置可以是第三方url链接
* <loc> ：一个日志格式变量 （或简单的字符串redirect语句）描述了新位置
* code <code>（可选）：HTTP重定向的状态代码来执行。 此选项下的允许的状态码如下所示，默认为302
* if | unless :用于条件判断
* <condition> （可选）：用于匹配acl，一般为acl的名称

（2）前缀重定向
redirect prefix <loc> [code <code>] <option> [{if | unless} <condition>]
* <pfx>一个日志格式变量 （或简单的字符串redirect语句）描述了新的位置前缀。
* code <code>（可选）：HTTP重定向的状态代码来执行，默认302
* if | unless :用于条件判断
* <condition> （可选）：用于匹配acl，一般为acl的名称

（3）协议重定向（比如将http重定向到https）
redirect scheme <sch> [code <code>] <option> [{if | unless} <condition>]

<options>
drop-query 在执行串联时从原来的URL删除查询字符串
append-slash 配合使用drop-query ，在该URL的末尾添加一个“/”字符
set-cookie NAME[=value] 一个Set-Cookie头部被添加到重定向。该cookie被命名为名称，可以有一个可选的值值。
clear-cookie NAME[=] 一个特殊的Set-Cookie头被添加到重定向。该Cookie名为名称和最大年龄的cookie参数设置为0，目的是为了指示浏览器删除cookie。

案例：
acl clear      dst_port  80
acl secure     dst_port  8080
acl login_page url_beg   /login
acl logout     url_beg   /logout
acl uid_given  url_reg   /login?userid=[^&]+
acl cookie_set hdr_sub(cookie) SEEN=1

redirect prefix   https://mysite.com set-cookie SEEN=1 if !cookie_set
redirect prefix   https://mysite.com           if login_page !secure
redirect prefix   http://mysite.com drop-query if login_page !uid_given
redirect location http://mysite.com/           if !login_page secure
redirect location / clear-cookie USERID=       if logout



redir重定向的用法:(redir通常配置在haproxy backend部分)

注意：使用redir 会将发往backend的站点服务请求均以302状态响应发给需要重定向的server服务或站点，在prefix后面不能使用/，且不能使用相对地址


案例：
acl www_c_com hdr_beg(host) -i www.c.com
use_backend test_www_c_com if www_c_com
backend test_www_c_com
  balance roundrobin
  server s1 192.168.10.162:8080 check redir http://www.baidu.com


