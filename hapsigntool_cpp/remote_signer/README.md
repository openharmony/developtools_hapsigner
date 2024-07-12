### Linux 环境生成远程签名动态库：  
1. 进入 src 目录  
2. 执行命令  
   ```bash
   g++ pkcs12_parser.cpp remote_signer.cpp -o libRemoteSigner.so -shared -fPIC -I ~/OPENSSL/include -I ../include -lcrypto
   ```
#### 解释：  
- g++：GNU 的 C++ 编译器  
- pkcs12_parser.cpp remote_signer.cpp：要编译的 C++ 源文件  
- -o libRemoteSigner.so：输出一个名为 libRemoteSigner.so 的动态库  
- -shared：告诉编译器要生成一个动态库  
- -fPIC："Position Independent Code"，生成位置无关的代码，对于动态库是必需的，因为动态库可以被加载到进程的任何内存地址  
- -I ~/OPENSSL/include：在 ~/OPENSSL/include 目录下查找 OpenSSL 的头文件  
- -I ../include: 在 ../include 目录下查找生成动态库所需的头文件  
- -lcrypto：链接到OpenSSL 的加密库 crypto  

### 在 main.cpp 中进行测试：  
1. 进入 demo 目录  
2. 执行命令  
   ```bash
   g++ main.cpp remote_sign_provider.cpp signer_factory.cpp -ldl -I ~/OPENSSL/include -I ../include
   ```
3. 执行可执行文件  
   ```bash
   ./a.out
   ```
### 注意：
**1. 在 Linux 环境下编译时，需要先将 hilog 日志屏蔽！**  
**2. 在 OpenHarmony 开发板上进行远程签名时，需要设置开发板时间为当前时间！**  
**3. 生成远程签名动态库所需要的环境如下。为保证正常生成动态库，以下属性需要同步更改！**  
- 证书链文件 ( appCertFile )：app-release1.pem ( signServer 代替)  
- 密钥库文件 ( keystoreFile )：OpenHarmony.p12 ( onlineAuthMode 代替)  
- 密钥别名 ( keyAlias )：oh-app1-key-v1 ( keyAlias 代替)  
- 密钥库口令 ( keystorePwd )：123456 ( username 代替)  
- 密钥口令 ( keyPwd )：123456 ( userPwd 代替)