背景：Oracle数据库装在本机上，使用PLSQL连接。今天安装完Oracle 11g数据库后，用plsql连接数据库死活都连接不上。并且plsql客户端登录窗口的Database下拉框还为空。见下图：
Oracle服务和监听已经开启，并且检查了相关的配置都没有问题。后来去网上搜索了下，发现有人说plsql不能直接连接64位 Oracle 11g数据库。
因为plsql是32位的，要想连接64位的数据库还需要安装一个32位的Oracle客户端。。
记得以前使用Oracle10g 数据库的时候就没有这个事啊，用plsql就可以直接连接数据库。

解决方案：
1、下载Oracle客户端：instantclient-basic-win32-11.2.0.1.0.zip
(点击下载Oracle32位客户端），
将其解压至Oracle安装目录的Product下：D:\app\NiuNiu\product\instantclient_11_2。

2、拷贝文件：将数据库安装目录D:\app\NiuNiu\product\11.2.0\dbhome_1\NETWORK\ADMIN
下的tnsnames.ora文件拷贝到客户端文件夹里。

3、配置PLSQL Developer：在Tools-》perference-》Connection里面设置Oracle_Home和OCI Library，
例如本机设置为：

Oracle Home ：E:\oracle11g\product\instantclient_11_2 
OCI Library ：E:\oracle11g\product\instantclient_11_2\oci.dll 


--  下边不用设置也可以

4、设置环境变量： 修改变量：在Path里添加：D:\app\NiuNiu\product\instantclient_11_2；

新建变量：名为”TNS_ADMIN”, 值为”D:\app\NiuNiu\product\instantcli