# Hap包签名工具

* 介绍
* 目录
* 安装教程
* 使用说明
* 一键签名脚本
* (附)命令说明

#### 介绍
为了保证OpenHarmony应用的完整性和来源可靠，在应用构建时需要对应用进行签名，才能在使用真机设备上安装、运行和调试该应用。本仓提供了一个具有证书生成、hap包签名等功能的jar工具包。

#### 目录

    developtools_hapsigner

    ├── autosign        # 一键签名脚本
    ├── docs         # 说明文档
    ├── hapsigntool     # 主代码
          ├──hap_sign_tool # 主程序入口，完成输入参数的基础校验
          ├──hap_sign_tool_lib  # 签名工具库，解析命令字和参数列表，实现各模块逻辑功能
    ├── tools   # 自动化测试脚本


#### 安装教程
1. 配置编译环境 ：Gradle 7.1，JDK 8
2. 下载代码
3. 命令行打开文件至developtools_hapsigner/hapsigntool目录下
4. **gradle build** 或 **gradle jar**编译生成jar
5. 文件在./hap_sign_tool/build/libs/hap_sign_tool-xxxx.jar

#### 使用说明
命令示例：

```shell
java -jar <签名工具.jar> <命令> <参数...>
```

完整使用示例：
```shell
java -jar hap_sign_tool.jar generate-csr -keyAlias "oh-app1-key-v1" -keyPwd ***** -subject  "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release" -signAlg SHA256withECDSA  -keystoreFile  "D:\OH\ohtest.jks" -keystorePwd ***** -outFile "D:\OH\oh-app1-key-v1.csr"
```

也可以使用 -help 查看完整使用说明
```shell
java -jar hap_sign_tool.jar -help
```
****

#### 一键签名脚本
使用一键签名脚本，免于输入繁杂的命令

打开本项目子目录autosign可见：
* start_create.sh/start_create.bat
* start_sign.sh/start_sign.bat
* auto_sign_main.py
* auto_sign.conf

操作流程
1. 脚本依赖环境python3.x
2. 脚本依赖hap_sign_tool.jar（参照上文编译生成的产物）
3. 准备好待签名的应用hap包和Provision profile模板文件
4. 使用文本编辑器编辑auto_sign.conf，补全配置文件中的配置
5. Linux运行start_create.sh、Windows运行start_create.bat生成签名所需文件
6. Linux运行start_sign.sh、Windows运行start_sign.bat对hap包进行签名

****
#### (附)命令说明：
##### 生成密钥对
* generate-keypair : 生成密钥对
  * -keyAlias : 密钥别名，必填项；
  * -keyPwd : 密钥口令，可选项；
  * -keyAlg : 密钥算法，必填项，包括RSA/ECC；
  * -keySize : 密钥长度，必填项，RSA算法的长度为2048/3072/4096，ECC算法的长度NIST-P-256/NIST-P-384;
  * -keystoreFile : 密钥库文件，必填项，JKS或P12格式；
  * -keystorePwd : 密钥库口令，可选项；

##### 生成证书签名请求
* generate-csr : 生成证书签名请求
  * -keyAlias : 密钥别名，必填项；
  * -keyPwd : 密钥口令，可选项；
  * -subject : 证书主题，必填项；
  * -signAlg : 签名算法，必填项，包括SHA256withRSA / SHA384withRSA / SHA256withECDSA / SHA384withECDSA；
  * -keystoreFile : 密钥库文件，必填项，JKS或P12格式；
  * -keystorePwd : 密钥库口令，可选项；
  * -outFile : 输出文件，可选项，如果不填，则直接输出到控制台；

##### 生成根CA/子CA证书
* generate-ca : 生成根CA/子CA证书，如果密钥不存在，一起生成密钥
  * -keyAlias : 密钥别名，必填项；
  * -keyPwd : 密钥口令，可选项；
  * -keyAlg : 密钥算法，必填项，包括RSA/ECC；
  * -keySize : 密钥长度，必填项，RSA算法的长度为2048/3072/4096，ECC算法的长度NIST-P-256/NIST-P-384;
  * -issuer : 颁发者的主题，可选项，如果不填，表示根CA
  * -issuerKeyAlias : 颁发者的密钥别名，可选项，如果不填，表示根CA；
  * -issuerKeyPwd : 颁发者的密钥口令，可选项
  * -subject : 证书主题，必填项；
  * -validity : 证书有效期，可选项，默认为3650天；
  * -signAlg : 签名算法，必填项，包括SHA256withRSA / SHA384withRSA / SHA256withECDSA / SHA384withECDSA；
  * -basicConstraintsPathLen : 路径长度，可选项，默认为0；
  * -keystoreFile : 密钥库文件，必填项，JKS或P12格式；
  * -keystorePwd : 密钥库口令，可选项；
  * -outFile : 输出证书文件，可选项，如果不填，则直接输出到控制台；

##### 生成应用调试/发布证书
* generate-app-cert : 生成应用调试/发布证书
  * -keyAlias : 密钥别名，必填项；
  * -keyPwd : 密钥口令，可选项；
  * -issuer : 颁发者的主题，必填项；
  * -issuerKeyAlias : 颁发者的密钥别名，必填项；
  * -issuerKeyPwd : 颁发者的密钥口令，可选项；
  * -subject : 证书主题，必填项；
  * -validity : 证书有效期，可选项，默认为1095天；
  * -signAlg : 签名算法，必填项，包括SHA256withECDSA / SHA384withECDSA；
  * -keystoreFile : 密钥库文件，必填项，JKS或P12格式；
  * -keystorePwd : 密钥库口令，可选项；
  * -outForm: 输出证书文件的格式，包括 cert / certChain，可选项，默认为certChain；
  * -rootCaCertFile: outForm为certChain时必填，根CA证书文件；
  * -subCaCertFile: outForm为certChain时必填，二级子CA证书文件；
  * -outFile : 输出证书文件(证书或证书链)，可选项，如果不填，则直接输出到控制台；

##### 生成应用调试/发布证书
* generate-profile-cert : 生成profile调试/发布证书
  * -keyAlias : 密钥别名，必填项；
  * -keyPwd : 密钥口令，可选项；
  * -issuer : 颁发者的主题，必填项；
  * -issuerKeyAlias : 颁发者的密钥别名，必填项；
  * -issuerKeyPwd : 颁发者的密钥口令，可选项；
  * -subject : 证书主题，必填项；
  * -validity : 证书有效期，可选项，默认为1095天；
  * -signAlg : 签名算法，必填项，包括SHA256withECDSA / SHA384withECDSA；
  * -keystoreFile : 密钥库文件，必填项，JKS或P12格式；
  * -keystorePwd : 密钥库口令，可选项；
  * -outForm: 输出证书文件的格式，包括 cert / certChain，可选项，默认为certChain；
  * -rootCaCertFile: outForm为certChain时必填，根CA证书文件；
  * -subCaCertFile: outForm为certChain时必填，二级子CA证书文件；
  * -outFile : 输出证书文件(证书或证书链)，可选项，如果不填，则直接输出到控制台；

##### 通用证书生成，可以生成自定义证书
* generate-cert : 通用证书生成，可以生成自定义证书
  * -keyAlias : 密钥别名，必填项；
  * -keyPwd : 密钥口令，可选项；
  * -issuer : 颁发者的主题，必填项；
  * -issuerKeyAlias : 颁发者的密钥别名，必填项；
  * -issuerKeyPwd : 颁发者的密钥口令，可选项；
  * -subject : 证书主题，必填项；
  * -validity : 证书有效期，可选项，默认为1095天；
  * -keyUsage : 密钥用法，必选项，包括digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, certificateSignature, crlSignature, encipherOnly和decipherOnly，如果证书包括多个密钥用法，用逗号分隔；
  * -keyUsageCritical : keyUsage是否为关键项，可选项，默认为是；
  * -extKeyUsage : 扩展密钥用法，可选项，包括clientAuthentication，serverAuthentication，codeSignature，emailProtection，smartCardLogin，timestamp，ocspSignature；
  * -extKeyUsageCritical : extKeyUsage是否为关键项，可选项，默认为否；
  * -signAlg : 签名算法，必填项，包括SHA256withRSA / SHA384withRSA / SHA256withECDSA / SHA384withECDSA；
  * -basicConstraints : 是否包含basicConstraints，可选项，默认为否；
  * -basicConstraintsCritical : basicConstraints是否包含为关键项，可选项，默认为否；
  * -basicConstraintsCa : 是否为CA，可选项，默认为否；
  * -basicConstraintsPathLen : 路径长度，可选项，默认为0；
  * -keystoreFile : 密钥库文件，必填项，JKS或P12格式；
  * -keystorePwd : 密钥库口令，可选项；
  * -outFile : 输出证书文件，可选项，如果不填，则直接输出到控制台；

##### ProvisionProfile文件签名
* sign-profile : ProvisionProfile文件签名
  * -mode : 签名模式，必填项，包括localSign，remoteSign；
  * -keyAlias : 密钥别名，必填项；
  * -keyPwd : 密钥口令，可选项；
  * -profileCertFile : Profile签名证书（证书链，顺序为三级-二级-根），必填项；
  * -inFile : 输入的原始Provision Profile文件，必填项；
  * -signAlg : 签名算法，必填项，包括SHA256withECDSA / SHA384withECDSA；
  * -keystoreFile : 密钥库文件，localSign模式时为必填项，JKS或P12格式；
  * -keystorePwd : 密钥库口令，可选项；
  * -outFile : 输出签名后的Provision Profile文件，p7b格式，必填项；

##### ProvisionProfile文件验签
* verify-profile : ProvisionProfile文件验签
  * -inFile：已签名的Provision Profile文件，p7b格式，必填项；
  * -outFile：验证结果文件（包含验证结果和profile内容），json格式，可选项；如果不填，则直接输出到控制台；

##### hap应用包签名
* sign-app : hap应用包签名
  * -mode：签名模式，必填项，包括localSign，remoteSign，remoteResign；
  * -keyAlias：密钥别名，必填项；
  * -keyPwd：密钥口令，可选项；
  * -appCertFile：应用签名证书文件（证书链，顺序为三级-二级-根），必填项；
  * -profileFile：签名后的Provision Profile文件名，p7b格式，必填项；
  * -profileSigned：指示profile文件是否带有签名，1表示有签名，0表示没有签名，默认为1。可选项；
  * -inForm：输入的原始文件的格式，zip格式或bin格式，默认zip格式；可选项；
  * -inFile：输入的原始APP包文件，hap格式或bin格式，必填项；
  * -signAlg：签名算法，必填项，包括SHA256withECDSA / SHA384withECDSA；
  * -keystoreFile：密钥库文件，localSign模式时为必填项，JKS或P12格式；
  * -keystorePwd: 密钥库口令，可选项；
  * -outFile: 输出签名后的包文件，必填项；

##### hap应用包文件验签
* verify-app : hap应用包文件验签
  * -inFile：已签名的应用包文件，hap格式或bin格式，必填项；
  * -outCertchain：签名的证书链文件，必填项；
  * -outProfile：应用包中的profile文件，必填项；
  