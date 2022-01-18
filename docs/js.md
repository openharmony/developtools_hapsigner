# API接口说明


对外接口实现类。提供创建密钥对、CSR、CA证书、三级证书、应用包的签名和验签、Profile文件的签名和验签方法。

## 导入模块
在使用ServiceApi的功能前，需要通过new SignToolServiceImpl()先获取ServiceApi对象。
```java
import com.ohos.hapsigntool.api.ServiceApi;
ServiceApi api = new SignToolServiceImpl();
```

## 方法

方法的具体调用形式：

api.generateKeyStore

方法名称：
* generateKeyStore(Options options);
* generateCsr(Options options);
* generateCert(Options options);
* generateCA(Options options);
* generateAppCert(Options options);
* generateProfileCert(Options options);
* signHap(Options options);
* verifyHap(Options options);
* signProfile(Options options);
* verifyProfile(Options options);

返回值类型:
boolean

方法描述：
* generateKeyStore：生成密钥对
* generateCsr：生成CSR
* generateCert：生成自定义证书
* generateCA：生成CA证书
* generateAppCert：生成app证书
* generateProfileCert：生成Profile证书
* signHap：应用包签名
* verifyHap：应用包验签
* signProfile：Profile文件签名
* verifyProfile：Profile文件验签

**参数：**

| 参数名                 | 类型      | 必填   | 说明                   |
|---------------------|---------|------|----------------------|
| options             | Options | 是    | 包含证书基本信息 |

**返回值**：

| 类型                                         | 说明         |
|--------------------------------------------|------------|
| boolean                                    | 判断方法是否正常执行 |

