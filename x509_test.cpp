/*
测试功能：openssl用根证书验证一个用户证书
参考链接：http://www.voidcn.com/article/p-eaqpfocp-t.html
测试方法：./x509_test ca.crt server.crt testca.crl     //完成ca对server证书的认证，但是server证书已被吊销在crl列表中，应认证不通过
		  ./x509_test ca.crt client.crt testca.crl     //完成ca对client证书的认证，client未被吊销，应该认证通过
		  ./x509_test ca1.crt client.crt testca.crl    //完成ca1对client证书的认证，client不是ca1签发的证书，应认证不通过
*/

#include <iostream>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

using namespace std;

#define USER_CERT "server.pem"         // 这里保存的是pem格式或crt格式证书
#define CA_CERT   "ca.pem"

int main(int argc, char **argv)
{
	//判断参数个数是否正确
	if(argc != 4)
	{
		printf("usage: %s ca_crt user_crt crl_file\n",argv[0]);
		return -1;
	}
	
	SSLeay_add_all_algorithms();

	X509_STORE_CTX *ctx = NULL;          // 证书存储区句柄
	X509_STORE *pCaCertStore = NULL;     // 证书存储区
	X509 *pCert = NULL;                  // X509 证书结构体，保存用户证书
	X509 *pCaCert = NULL;                // X509 证书结构体，保存根证书
	X509_CRL *Crl = NULL;                // X509_CRL 结构体，保存CRL
	STACK_OF(X509) *CertStack = NULL;

	BIO * pbio = NULL;
	
	/*********************************第一步：读取用户证书*************************************************/
	pbio = BIO_new_file(argv[2],"r");
	pCert = PEM_read_bio_X509(pbio,NULL,NULL,NULL);
	if(pCert == NULL)
	{
	  X509_free(pCert);
	  cout<<"读取用户证书失败！"<<endl;
	  return -1;
	}
	BIO_free(pbio);
	pbio = NULL;
	/*********************************第二步：读取CA根证书*************************************************/
	pbio = BIO_new_file(argv[1],"r");
	pCaCert = PEM_read_bio_X509(pbio,NULL,NULL,NULL);
	if(pCaCert == NULL)
	{
	  X509_free(pCaCert);
	  cout<<"打开根证书失败"<<endl;
	  return -1;
	}
	BIO_free(pbio);
	pbio = NULL;
	/*********************************第三步：读取CA根证书*************************************************/
	//读取CRL文件
	pbio = BIO_new_file(argv[3],"r");
    Crl = PEM_read_bio_X509_CRL(pbio,NULL,NULL,NULL);
    if (Crl==NULL)
	{
        X509_CRL_free(Crl);
		cout<<"读取吊销列表文件失败"<<endl;
        return -1 ;
    }
	BIO_free(pbio);
	pbio = NULL;

	//1.创建证书存储区
    pCaCertStore = X509_STORE_new();     			//1.新建X509 证书存储区

    //设置检查CRL 标志位，如果设置此标志位，则检查CRL ，否则不检查CRL 。
	// X509_V_FLAG_IGNORE_CRITICAL 、
	// X509_V_FLAG_CB_ISSUER_CHECK 、
	// X509_V_FLAG_CRL_CHECK 、
	// X509_V_FLAG_CRL_CHECK│X509_V_FLAG_CRL_CHECK_ALL 等
	X509_STORE_set_flags(pCaCertStore,X509_V_FLAG_CRL_CHECK);				//验证CRL列表
	//X509_STORE_set_flags(pCaCertStore,X509_V_FLAG_IGNORE_CRITICAL);		//不验证CRL列表
	
    X509_STORE_add_cert(pCaCertStore,pCaCert);      // 2.添加根证书到证书存储区
    X509_STORE_add_crl(pCaCertStore,Crl);    		// 3.添加CRL到证书存储区

    ctx = X509_STORE_CTX_new();    			 		// 4.创建证书存储区上下文环境函数(产生一个操作句柄)

	//5.初始化证书存储区上下文环境(ctx)，设置根证书(pCaCertStore)、待验证的证书(pCert)、CA证书链(CertStack=NULL)。
    int ret = X509_STORE_CTX_init(ctx,pCaCertStore,pCert,CertStack);   
    if (ret != 1)
    {
       cout<<"X509_STORE_CTX_init err"<<endl;

       X509_free(pCert);
       X509_free(pCaCert);
       X509_STORE_CTX_cleanup(ctx);
       X509_STORE_CTX_free(ctx);
       X509_STORE_free(pCaCertStore);
       return -1 ;
    }
    //6.验证用户证书,返回1表示验证成功,返回0表示验证失败
    ret = X509_verify_cert(ctx); 
    if (ret != 1)
    {
	   cout<<"证书验证失败!"<<endl;
       cout<<"verify cer err.error="<<ctx->error<<"info:"<<X509_verify_cert_error_string(ctx->error)<<endl;
    }
	else{
	   cout<<"证书验证成功!"<<endl;
	}

    // 释放内存
    X509_free(pCert);			//释放用户证书打开后占用的内存
    X509_free(pCaCert);			//释放CA根证书打开后占用的内存
	X509_CRL_free(Crl);			//释放CRL吊销列表打开后占用的内存
    X509_STORE_CTX_cleanup(ctx);	  //清除ctx的上下文配置
    X509_STORE_CTX_free(ctx);		  //释放证书存储区上下文环境函数，释放句柄
    X509_STORE_free(pCaCertStore);    //释放证书存储区

	return 0; 
}