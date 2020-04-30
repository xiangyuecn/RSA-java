# :open_book:RSA-java的帮助文档

本项目核心功能：支持`Java`环境下`PEM`（`PKCS#1`、`PKCS#8`）格式RSA密钥对导入、导出。

底层实现采用PEM文件二进制层面上进行字节码解析，简单轻巧0依赖；附带实现了一个含有RSA加密解密操作测试控制台程序（双击`Start.bat`即可运行，前提装了JDK）。

你可以只copy `RSA_PEM.java` 文件到你的项目中使用（建好package目录或者修改一下package），只需这一个文件你就拥有了通过PEM格式密钥简单快速创建`RSA Cipher`的能力。clone整个项目代码双击`Start.bat`即可观摩效果，经目测看起来没什么卵用的文件都svn:ignore掉了（svn滑稽。

【C#版】：[RSA-csharp](https://github.com/xiangyuecn/RSA-csharp)，本Java项目从C#版移植。


## 特性

- 通过`XML格式`密钥对创建RSAPublicKey、RSAPrivateKey、Cipher
- 通过`PEM格式`密钥对创建RSAPublicKey、RSAPrivateKey、Cipher
- 导出`XML格式`公钥、私钥
- 导出`PEM格式`公钥、私钥
- `PEM格式`秘钥对和`XML格式`秘钥对互转



## 【QQ群】交流与支持

欢迎加QQ群：421882406，纯小写口令：`xiangyuecn`

<img src="https://gitee.com/xiangyuecn/Recorder/raw/master/assets/qq_group_421882406.png" width="220px">



# :open_book:文档

## 【RSA_PEM.java】

此文件不依赖任何文件，可以直接copy这个文件到你项目中用；通过`FromPEM`、`ToPEM` 和`FromXML`、`ToXML`这两对方法，可以实现PEM`PKCS#1`、`PKCS#8`相互转换，PEM、XML的相互转换。

注：openssl `RSAPublicKey_out`导出的公钥，字节码内并不带[OID](http://www.oid-info.com/get/1.2.840.113549.1.1.1)（目测是因为不带OID所以openssl自己都不支持用这个公钥来加密数据），RSA_PEM支持此格式公钥的导入，但不提供此种格式公钥的导出。

### 构造方法

**RSA_PEM(RSAPublicKey publicKey, RSAPrivateKey privateKeyOrNull)**：通过RSA中的公钥和私钥构造一个PEM，私钥可以不提供，导出的PEM就只包含公钥。

**RSA_PEM(byte[] modulus, byte[] exponent, byte[] d, byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] inverseQ)**：通过全量的PEM字段数据构造一个PEM，除了模数modulus和公钥指数exponent必须提供外，其他私钥指数信息要么全部提供，要么全部不提供（导出的PEM就只包含公钥）注意：所有参数首字节如果是0，必须先去掉。

**RSA_PEM(byte[] modulus, byte[] exponent, byte[] dOrNull)**：通过公钥指数和私钥指数构造一个PEM，会反推计算出P、Q但和原始生成密钥的P、Q极小可能相同。注意：所有参数首字节如果是0，必须先去掉。出错将会抛出异常。私钥指数可以不提供，导出的PEM就只包含公钥。


### 实例属性

byte[]：**Key_Modulus**(模数n，公钥、私钥都有)、**Key_Exponent**(公钥指数e，公钥、私钥都有)、**Key_D**(私钥指数d，只有私钥的时候才有)；有这3个足够用来加密解密。

byte[]：**Val_P**(prime1)、**Val_Q**(prime2)、**Val_DP**(exponent1)、**Val_DQ**(exponent2)、**Val_InverseQ**(coefficient)； (PEM中的私钥才有的更多的数值；可通过n、e、d反推出这些值（只是反推出有效值，和原始的值大概率不同）)。

int：**keySize()**(密钥位数)

boolean：**hasPrivate()**(是否包含私钥)


### 实例方法

**RSAPublicKey getRSAPublicKey()**：得到公钥Java对象。

**RSAPrivateKey getRSAPrivateKey()**：得到私钥Java对象，如果此PEM不含私钥会直接报错。

**String ToPEM(boolean convertToPublic, boolean usePKCS8)**：将RSA中的密钥对转换成PEM格式，usePKCS8=false时返回PKCS#1格式，否则返回PKCS#8格式，如果convertToPublic含私钥的RSA将只返回公钥，仅含公钥的RSA不受影响。

**String ToXML(boolean convertToPublic)**：将RSA中的密钥对转换成XML格式，如果convertToPublic含私钥的RSA将只返回公钥，仅含公钥的RSA不受影响。


### 静态方法

**static RSA_PEM FromPEM(String pem)**：用PEM格式密钥对创建RSA，支持PKCS#1、PKCS#8格式的PEM，出错将会抛出异常。pem格式如：`-----BEGIN XXX KEY-----....-----END XXX KEY-----`。

**static RSA_PEM FromXML(String xml)**：将XML格式密钥转成PEM，支持公钥xml、私钥xml，出错将会抛出异常。


## 如何加密、解密、签名、校验
得到了RSA_PEM后，加密解密就异常简单了，没那么多啰嗦难懂的代码。
``` java
RAS_PEM pem=RSA_PEM.FromPEM("-----BEGIN XXX KEY-----..此处意思意思..-----END XXX KEY-----");

//通过公钥构造加密Cipher
Cipher enc = Cipher.getInstance("RSA");
enc.init(Cipher.ENCRYPT_MODE, pem.getRSAPublicKey());
byte[] en = enc.doFinal("测试123".getBytes("utf-8"));

//通过私钥构造解密Cipher
Cipher dec = Cipher.getInstance("RSA");
dec.init(Cipher.DECRYPT_MODE, pem.getRSAPrivateKey());
byte[] de = dec.doFinal(en);
String deTxt=new String(de,"utf-8");//测试123

//通过私钥构造签名对象
Signature signature=Signature.getInstance("SHA1WithRSA");
signature.initSign(pem.getRSAPrivateKey());
signature.update("测试123".getBytes("utf-8"));
byte[] signBytes=signature.sign();

//通过公钥构造签名校验对象
Signature signVerify=Signature.getInstance("SHA1WithRSA");
signVerify.initVerify(pem.getRSAPublicKey());
signVerify.update("测试123".getBytes("utf-8"));
boolean isVerify=signVerify.verify(signBytes);
```

更多的实例，请阅读`Test.java`。


# :open_book:图例

控制台运行：

![控制台运行](images/1.png)

RSA工具（非开源）：

![RSA工具](https://gitee.com/xiangyuecn/RSA-csharp/raw/master/images/2.png)



# :open_book:知识库

请移步到[RSA-csharp](https://github.com/xiangyuecn/RSA-csharp)阅读知识库部分，知识库内包含了详细的PEM格式解析，和部分ASN.1语法；然后逐字节分解PEM字节码教程。

本库的诞生是由于微信付款到银行卡的功能，然后微信提供的RSA公钥接口返回的公钥和openssl -RSAPublicKey_out生成的一样，公钥 PEM 字节码内没有OID（目测是因为不带 OID 所以openssl 自己都不支持用这个公钥来加密数据）,这种是不是PKCS#1 格式不清楚，正反都是难用，所以就撸了一个java版转换代码，也不是难事以前撸过C#的，copy C#的代码过来改改就上线使用了。

本库的代码整理未使用IDE，RSA_PEM.java copy过来的，Test.java直接用的文本编辑器编写，*.java文件全部丢到根目录，没有创建包名目录，源码直接根目录裸奔，简单粗暴；这样的项目结构肉眼看去也算是简洁，也方便copy文件使用。


# :star:捐赠
如果这个库有帮助到您，请 Star 一下。

您也可以使用支付宝或微信打赏作者：

![](https://gitee.com/xiangyuecn/Recorder/raw/master/assets/donate-alipay.png)  ![](https://gitee.com/xiangyuecn/Recorder/raw/master/assets/donate-weixin.png)
