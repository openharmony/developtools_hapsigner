# 签名库开发指导


## 场景介绍
签名库主要提供了以下功能：
* 秘钥对生成
* 证书签发
* profile签名
* hap应用签名


## 接口说明


签名库开放能力如下：SignToolServiceImpl类，具体的API详见接口文档。

**表1**  签名库API接口功能介绍

| 接口名 | 描述 |
| -------- | -------- |
| boolean generateKeyStore(Options options) | 生成秘钥对，并保存至对应秘钥库 |
| boolean generateCsr(Options options) | 生成证书请求 csr |
| boolean generateCert(Options options) | 通用证书生成方法 |
| boolean generateCA(Options options) | 生成一二级证书 |
| boolean generateAppCert(Options options) | 生成App签名证书（三级证书） |
| boolean generateProfileCert(Options options) | 生成Profile签名证书（三级证书） |
| boolean signProfile(Options options) | 对Profile文件进行签名 |
| boolean verifyProfile(Options options) | 对已签名profile(.p7b)文件进行验证 |
| boolean signHap(Options options) | 对未签名鸿蒙应用进行签名 |
| boolean verifyHap(Options options) | 对已签名应用包文件进行验证） |


## 开发步骤

1. 使用签名库，需要初始化 ServiceApi
```
    ServiceApi api = new SignToolServiceImpl();
```
2. 根据使用目的，完成参数填入
```java
    Options options = new Options();
    options.put(Options.ISSUER, "subject");
    options.put(Options.SIGN_ALG, "SHA384withRSA");
    ...
```
3. 调用对应接口，完成使用
```java
    api.generateCA(params);
```

