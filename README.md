# certificate-authentication  
基于openssl工具实现CA对用户证书的认证   
### 操作原理：   
1.使用openssl工具可以完成自建CA，并使用该自建CA为其他用户user签发证书，具体自建CA及证书颁发的方法可参考本人的博客：   
<https://blog.csdn.net/weixin_42700740/article/details/117527769>   
2.可借助openssl提供的有关库函数完成CA对用户证书的验证，即确定该证书是否为本CA所签发的。    
3.在CA验证用户证书的过程中可查看CRL列表以确定用户证书是否被吊销。    
### 验证方法：   
1.确保opesnssl工具在linux环境中安装成功。    
2.make编译x509_test.cpp源代码。   
3.执行验证：   
运行：```./x509_test ca.crt server.crt testca.crl```   
&#8195;&#8195;完成ca对server证书的认证，但是server证书已被吊销在crl列表中，认证结果为不通过。    
运行：```./x509_test ca.crt client.crt testca.crl```   
&#8195;&#8195;完成ca对client证书的认证，client未被吊销，验证结果为认证通过。    
运行：```x509_test ca1.crt client.crt testca.crl```   
&#8195;&#8195;完成ca1对client证书的认证，client不是ca1签发的证书，认证结果为不通过。   
