**【[源GitHub仓库](https://github.com/xiangyuecn/RSA-java)】 | 【[Gitee镜像库](https://gitee.com/xiangyuecn/RSA-java)】如果本文档图片没有显示，请手动切换到Gitee镜像库阅读文档。**

# :open_book:RSA-java使用文档 ( [English Documentation](README-English.md) )

**本项目核心功能：支持`Java`环境下`PEM`（`PKCS#1`、`PKCS#8`）格式RSA密钥生成、导入、导出，多种常见RSA加密、签名填充算法支持。**

- 支持Java8(1.8)及以上版本
- 可通过`PEM`、`XML`格式密钥创建RSA
- 可通过指定密钥位数、密钥参数创建RSA
- 可导出`PEM`、`XML`格式公钥、私钥，格式相互转换
- 公钥加密、私钥解密：`NoPadding`、`PKCS1Padding`、`OAEP+MD5`、`OAEP+SHA1 ... SHA3-512`
- 私钥签名、公钥验证：`PKCS1+SHA1 ... SHA3-512`、`PKCS1+MD5`、`PSS+SHA1 ... SHA3-512`
- 非常规的：私钥加密、公钥解密，公钥签名、私钥验证
- 多语言支持：提供中文、英文两种语言支持
- 另有C#版 [RSA-csharp](https://github.com/xiangyuecn/RSA-csharp)，所有加密签名算法在`Java`、`.NET`、`OpenSSL`中均可互通
- 源码简单，提供编译测试`.bat|.sh`脚本，无需IDE即可修改和运行，copy即用

[​](?)

你可以只copy `RSA_PEM.java`、`RSA_Util.java` 文件到你的项目中使用，即可使用上所有的功能。也可以clone整个项目代码双击 `Test-Build-Run.bat` 即可直接运行测试（macOS、linux用终端运行`.sh`的），通过`scripts/Create-jar.bat(sh)`脚本可打包成jar文件供项目引用。

`RSA_PEM`类底层实现采用PEM文件二进制层面上进行字节码解析，简单轻巧0依赖；`RSA_Util`为封装RSA操作类，在高版本Java下支持大部分加密签名模式，另可选搭配使用`BouncyCastle`的jar加密增强包可获得更丰富的加密签名模式支持。


[​](?)

**Test-Build-Run.bat 测试编译运行截图：**

![控制台测试](images/1.png)


[​](?)

[​](?)

## 快速使用：加密、解密、签名、校验

### 步骤一：引入RSA-java
- 方法1：直接复制 `RSA_PEM.java`、`RSA_Util.java` 文件到你的项目中使用。
- 方法2：使用`scripts/Create-jar.bat(sh)`脚本打包生成jar，项目里添加这个jar包即可使用。
- 方法3：下载Releases中的jar文件（就是方法2脚本打包出的jar），项目里添加这个jar包即可使用。


### 步骤二：编写代码
``` java
//先解析pem或xml，公钥私钥均可解析 
//RSA_PEM pem=RSA_PEM.FromPEM("-----BEGIN XXX KEY-----....-----END XXX KEY-----");
//RSA_PEM pem=RSA_PEM.FromXML("<RSAKeyValue><Modulus>....</RSAKeyValue>");

//直接创建RSA操作类，可创建成全局对象，加密解密签名均支持并发调用
//RSA_Util rsa=new RSA_Util(pem);
RSA_Util rsa=new RSA_Util(2048); //也可以直接生成新密钥，rsa.ToPEM()得到pem对象

//可选注册BouncyCastle的jar加密增强包（程序启动时注册一次即可），用来兼容低版本Java，和实现Java不支持的加密签名填充方式；可到 https://www.bouncycastle.org/latest_releases.html 下载 bcprov-jdk**-**.jar
//Security.addProvider(new BouncyCastleProvider());
//RSA_Util.UseBouncyCastle(BouncyCastleProvider.PROVIDER_NAME);

//公钥加密，填充方式：PKCS1，可以使用 OAEP+SHA256 等填充方式
String enTxt=rsa.Encrypt("PKCS1", "测试123");
//私钥解密
String deTxt=rsa.Decrypt("PKCS1", enTxt);

//私钥签名，填充方式：PKCS1+SHA1，可以使用 PSS+SHA256 等填充方式
String sign=rsa.Sign("PKCS1+SHA1", "测试123");
//公钥校验签名
boolean isVerify=rsa.Verify("PKCS1+SHA1", sign, "测试123");

//导出pem文本
String pemTxt=rsa.ToPEM(false).ToPEM_PKCS8(false);

//非常规的（不安全、不建议使用）：私钥加密、公钥解密，公钥签名、私钥验证
RSA_Util rsaS_Private=rsa.SwapKey_Exponent_D__Unsafe();
RSA_Util rsaS_Public=new RSA_Util(rsa.ToPEM(true)).SwapKey_Exponent_D__Unsafe();
//... rsaS_Private.Encrypt rsaS_Public.Decrypt
//... rsaS_Public.Sign rsaS_Private.Verify

System.out.println(pemTxt+"\n"+enTxt+"\n"+deTxt+"\n"+sign+"\n"+isVerify);
//****更多的实例，请阅读 Test.java****
//****更多功能方法，请阅读下面的详细文档****
```

**如需功能定制，网站、App、小程序开发等需求，请加下面的QQ群，联系群主（即作者），谢谢~**



[​](?)

## 【QQ群】交流与支持

欢迎加QQ群：421882406，纯小写口令：`xiangyuecn`

<img src="https://gitee.com/xiangyuecn/Recorder/raw/master/assets/qq_group_421882406.png" width="220px">






[​](?)

[​](?)

[​](?)

[​](?)

[​](?)

[​](?)

# :open_book:文档

## 加密填充方式

> 下表中BC为BouncyCastle的jar加密增强包支持情况（可通过RSA_Util.UseBouncyCastle方法注册）；√为支持，×为不支持，其他值为某版本开始支持（Java9）；其中OAEP的掩码生成函数MGF1使用和OAEP相同的Hash算法，加密解密实现代码中统一采用："RSA/ECB/OAEPPadding"模式+配置参数 这种形式进行Java底层调用；Java的RSA默认是PKCS1填充方式（Android默认是NoPadding？）。

加密填充方式|Algorithm|Java|BC
:-|:-|:-:|:-:
NO|RSA/ECB/NoPadding|√|√
PKCS1      |RSA/ECB/PKCS1Padding|√|√
OAEP+SHA1  |RSA/ECB/OAEPwithSHA-1andMGF1Padding|√|√
OAEP+SHA256|RSA/ECB/OAEPwithSHA-256andMGF1Padding|√|√
OAEP+SHA224|RSA/ECB/OAEPwithSHA-224andMGF1Padding|√|√
OAEP+SHA384|RSA/ECB/OAEPwithSHA-384andMGF1Padding|√|√
OAEP+SHA512|RSA/ECB/OAEPwithSHA-512andMGF1Padding|√|√
OAEP+SHA-512/224|RSA/ECB/OAEPwithSHA-512/224andMGF1Padding|9+|√
OAEP+SHA-512/256|RSA/ECB/OAEPwithSHA-512/256andMGF1Padding|9+|√
OAEP+SHA3-256|RSA/ECB/OAEPwithSHA3-256andMGF1Padding|9+|√
OAEP+SHA3-224|RSA/ECB/OAEPwithSHA3-224andMGF1Padding|9+|√
OAEP+SHA3-384|RSA/ECB/OAEPwithSHA3-384andMGF1Padding|9+|√
OAEP+SHA3-512|RSA/ECB/OAEPwithSHA3-512andMGF1Padding|9+|√
OAEP+MD5     |RSA/ECB/OAEPwithMD5andMGF1Padding|√|√



## 签名填充方式

> 下表中BC为BouncyCastle的jar加密增强包支持情况（可通过RSA_Util.UseBouncyCastle方法注册）；√为支持，×为不支持，其他值为某版本开始支持（Java11）；其中PSS的salt字节数等于使用的Hash算法字节数，PSS的掩码生成函数MGF1使用和PSS相同的Hash算法，跟踪属性TrailerField取值固定为0xBC，签名实现代码中统一采用："RSASSA-PSS"模式+配置参数 这种形式进行Java底层调用。

签名填充方式|Algorithm|Java|BC
:-|:-|:-:|:-:
SHA1 ... SHA3-512|等同于PKCS1+SHA***||
PKCS1+SHA1  |SHA1withRSA|√|√
PKCS1+SHA256|SHA256withRSA|√|√
PKCS1+SHA224|SHA224withRSA|√|√
PKCS1+SHA384|SHA384withRSA|√|√
PKCS1+SHA512|SHA512withRSA|√|√
PKCS1+SHA-512/224|SHA512/224withRSA|11+|√
PKCS1+SHA-512/256|SHA512/256withRSA|11+|√
PKCS1+SHA3-256|SHA3-256withRSA|16+|√
PKCS1+SHA3-224|SHA3-224withRSA|16+|√
PKCS1+SHA3-384|SHA3-384withRSA|16+|√
PKCS1+SHA3-512|SHA3-512withRSA|16+|√
PKCS1+MD5 |MD5withRSA|√|√
PSS+SHA1  |SHA1withRSA/PSS|11+|√
PSS+SHA256|SHA256withRSA/PSS|11+|√
PSS+SHA224|SHA224withRSA/PSS|11+|√
PSS+SHA384|SHA384withRSA/PSS|11+|√
PSS+SHA512|SHA512withRSA/PSS|11+|√
PSS+SHA-512/224|SHA512/224withRSA/PSS|11+|√
PSS+SHA-512/256|SHA512/256withRSA/PSS|11+|√
PSS+SHA3-256|SHA3-256withRSA/PSS|16+|√
PSS+SHA3-224|SHA3-224withRSA/PSS|16+|√
PSS+SHA3-384|SHA3-384withRSA/PSS|16+|√
PSS+SHA3-512|SHA3-512withRSA/PSS|16+|√
PSS+MD5     |MD5withRSA/PSS|×|√



[​](?)

[​](?)

## RSA_PEM 类文档
`RSA_PEM.java`文件不依赖任何文件，可以直接copy这个文件到你项目中用；通过`FromPEM`、`ToPEM` 和`FromXML`、`ToXML`这两对方法，可以实现PEM`PKCS#1`、`PKCS#8`相互转换，PEM、XML的相互转换。

注：`openssl rsa -in 私钥文件 -pubout`导出的是PKCS#8格式公钥（用的比较多），`openssl rsa -pubin -in PKCS#8公钥文件 -RSAPublicKey_out`导出的是PKCS#1格式公钥（用的比较少）。


### 静态属性和方法

`RSA_PEM` **FromPEM(String pem)**：用PEM格式密钥对创建RSA，支持PKCS#1、PKCS#8格式的PEM，出错将会抛出异常。pem格式如：`-----BEGIN XXX KEY-----....-----END XXX KEY-----`。

`RSA_PEM` **FromXML(String xml)**：将XML格式密钥转成PEM，支持公钥xml、私钥xml，出错将会抛出异常。xml格式如：`<RSAKeyValue><Modulus>....</RSAKeyValue>`。

`String` **T(String zh, String en)**：简版多语言支持，根据当前语言`Lang()`值返回中文或英文。

`String` **Lang()**、**SetLang(String lang)**：简版多语言支持，取值：`zh`（简体中文）、`en`（English-US），默认根据系统取值，可设为指定的语言。


### 构造方法

**RSA_PEM(RSAPublicKey publicKey, RSAPrivateKey privateKeyOrNull)**：通过RSA中的公钥和私钥构造一个PEM，私钥可以不提供，导出的PEM就只包含公钥。

**RSA_PEM(byte[] modulus, byte[] exponent, byte[] d, byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] inverseQ)**：通过全量的PEM字段数据构造一个PEM，除了模数modulus和公钥指数exponent必须提供外，其他私钥指数信息要么全部提供，要么全部不提供（导出的PEM就只包含公钥）注意：所有参数首字节如果是0，必须先去掉。

**RSA_PEM(byte[] modulus, byte[] exponent, byte[] dOrNull)**：通过公钥指数和私钥指数构造一个PEM，会反推计算出P、Q但和原始生成密钥的P、Q极小可能相同。注意：所有参数首字节如果是0，必须先去掉。出错将会抛出异常。私钥指数可以不提供，导出的PEM就只包含公钥。


### 实例属性

`byte[]`：**Key_Modulus**(模数n，公钥、私钥都有)、**Key_Exponent**(公钥指数e，公钥、私钥都有)、**Key_D**(私钥指数d，只有私钥的时候才有)；有这3个足够用来加密解密。

`byte[]`：**Val_P**(prime1)、**Val_Q**(prime2)、**Val_DP**(exponent1)、**Val_DQ**(exponent2)、**Val_InverseQ**(coefficient)； (PEM中的私钥才有的更多的数值；可通过n、e、d反推出这些值（只是反推出有效值，和原始的值大概率不同）)。

`int` **keySize()**：密钥位数。

`boolean` **hasPrivate()**：是否包含私钥。


### 实例方法

`RSAPublicKey` **getRSAPublicKey()**：得到公钥Java对象。

`RSAPrivateKey` **getRSAPrivateKey()**：得到私钥Java对象，如果此PEM不含私钥会直接报错。

`RSA_PEM` **CopyToNew(boolean convertToPublic)**：将当前PEM中的密钥对复制出一个新的PEM对象。convertToPublic：等于true时含私钥的PEM将只返回公钥，仅含公钥的PEM不受影响。

`RSA_PEM` **SwapKey_Exponent_D__Unsafe()**：【不安全、不建议使用】对调交换公钥指数（Key_Exponent）和私钥指数（Key_D）：把公钥当私钥使用（new.Key_D=this.Key_Exponent）、私钥当公钥使用（new.Key_Exponent=this.Key_D），返回一个新PEM对象；比如用于：私钥加密、公钥解密，这是非常规的用法。当前对象必须含私钥，否则无法交换会直接抛异常。注意：把公钥当私钥使用是非常不安全的，因为绝大部分生成的密钥的公钥指数为 0x10001（AQAB），太容易被猜测到，无法作为真正意义上的私钥。

`byte[]` **ToDER(boolean convertToPublic, boolean privateUsePKCS8, boolean publicUsePKCS8)**：将RSA中的密钥对转换成DER格式，DER格式为PEM中的Base64文本编码前的二进制数据，参数含义参考ToPEM方法。

`String` **ToPEM(boolean convertToPublic, boolean privateUsePKCS8, boolean publicUsePKCS8)**：将RSA中的密钥对转换成PEM格式。convertToPublic：等于true时含私钥的RSA将只返回公钥，仅含公钥的RSA不受影响 。**privateUsePKCS8**：私钥的返回格式，等于true时返回PKCS#8格式（`-----BEGIN PRIVATE KEY-----`），否则返回PKCS#1格式（`-----BEGIN RSA PRIVATE KEY-----`），返回公钥时此参数无效；两种格式使用都比较常见。**publicUsePKCS8**：公钥的返回格式，等于true时返回PKCS#8格式（`-----BEGIN PUBLIC KEY-----`），否则返回PKCS#1格式（`-----BEGIN RSA PUBLIC KEY-----`），返回私钥时此参数无效；一般用的多的是true PKCS#8格式公钥，PKCS#1格式公钥似乎比较少见。

`String` **ToPEM_PKCS1(boolean convertToPublic)**：ToPEM方法的简化写法，不管公钥还是私钥都返回PKCS#1格式；似乎导出PKCS#1公钥用的比较少，PKCS#8的公钥用的多些，私钥#1#8都差不多。

`String` **ToPEM_PKCS8(boolean convertToPublic)**：ToPEM方法的简化写法，不管公钥还是私钥都返回PKCS#8格式。

`String` **ToXML(boolean convertToPublic)**：将RSA中的密钥对转换成XML格式，如果convertToPublic含私钥的RSA将只返回公钥，仅含公钥的RSA不受影响。




[​](?)

[​](?)

## RSA_Util 类文档
`RSA_Util.java`文件依赖`RSA_PEM.java`，封装了加密、解密、签名、验证、秘钥导入导出操作。


### 静态属性和方法

`String` **RSAPadding_Enc(String padding)**：将加密填充方式转换成对应的Algorithm字符串，比如`PKCS1 -> RSA/ECB/PKCS1Padding`。

`String` **RSAPadding_Sign(String hash)**：将签名填充方式转换成对应的Algorithm字符串，比如`PKCS1+SHA1 -> SHA1withRSA`。

`boolean` **IsJavaLowVerSupportError(Throwable err)**：判断异常消息是否是因为低版本Java兼容性产生的错误。

`void` **UseBouncyCastle(String providerName)**：强制使用BouncyCastle的jar加密增强包进行RSA操作。只需在程序启动后调用一次即可，需先调用 `Security.addProvider(new BouncyCastleProvider())` 进行全局注册，然后再调用本方法进行启用：`UseBouncyCastle(BouncyCastleProvider.PROVIDER_NAME)`，传入null取消启用。项目中引入BouncyCastle加密增强包来扩充Java加密功能，先到 https://www.bouncycastle.org/latest_releases.html 下载 bcprov-jdk**-**.jar，在程序启动时调用本方法进行注册和启用即可得到全部的加密签名填充方式支持。

`boolean` **IsUseBouncyCastle()**：是否强制使用BouncyCastle的jar加密增强包进行RSA操作，为true时将不会使用Java的RSA实现。


### 构造方法

**RSA_Util(int keySize)**：用指定密钥大小创建一个新的RSA，会生成新密钥，出错抛异常。

**RSA_Util(String pemOrXML)**：通过`PEM格式`或`XML格式`密钥，创建一个RSA，pem或xml内可以只包含一个公钥或私钥，或都包含，出错抛异常。`XML格式`如：`<RSAKeyValue><Modulus>...</RSAKeyValue>`。pem支持`PKCS#1`、`PKCS#8`格式，格式如：`-----BEGIN XXX KEY-----....-----END XXX KEY-----`。

**RSA_Util(RSA_PEM pem)**：通过一个pem对象创建RSA，pem为公钥或私钥，出错抛异常。


### 实例属性

`RSAPublicKey` **publicKey**：RSA公钥。

`RSAPrivateKey` **privateKey**：RSA私钥，仅有公钥时为null。

`int` **keySize()**：密钥位数。

`boolean` **hasPrivate()**：是否包含私钥。


### 实例方法

`String` **ToXML(boolean convertToPublic)**：导出`XML格式`秘钥对，如果convertToPublic含私钥的RSA将只返回公钥，仅含公钥的RSA不受影响。

`RSA_PEM` **ToPEM(boolean convertToPublic)**：导出RSA_PEM对象（然后可以通过RSA_PEM.ToPEM方法导出PEM文本），如果convertToPublic含私钥的RSA将只返回公钥，仅含公钥的RSA不受影响。

`RSA_Util` **SwapKey_Exponent_D__Unsafe()**：【不安全、不建议使用】对调交换公钥指数（Key_Exponent）和私钥指数（Key_D）：把公钥当私钥使用（new.Key_D=this.Key_Exponent）、私钥当公钥使用（new.Key_Exponent=this.Key_D），返回一个新RSA对象；比如用于：私钥加密、公钥解密，这是非常规的用法。当前密钥如果是公钥，将不会发生对调，返回的新RSA将允许用公钥进行解密和签名操作。注意：把公钥当私钥使用是非常不安全的，因为绝大部分生成的密钥的公钥指数为 0x10001（AQAB），太容易被猜测到，无法作为真正意义上的私钥。部分私钥加密实现中，比如Java自带的RSA，使用非NoPadding填充方式时，用私钥对象进行加密可能会采用EMSA-PKCS1-v1_5填充方式（用私钥指数构造成公钥对象无此问题），因此在不同程序之间互通时，可能需要自行使用对应填充算法先对数据进行填充，然后再用NoPadding填充方式进行加密（解密也按NoPadding填充进行解密，然后去除填充数据）。

`String` **Encrypt(String padding, String str)**：加密任意长度字符串（utf-8）返回base64，出错抛异常。本方法线程安全。padding指定填充方式，如：PKCS1、OAEP+SHA256大写，参考上面的加密填充方式表格，使用空值时默认为PKCS1。

`byte[]` **Encrypt(String padding, byte[] data)**：加密任意长度数据，出错抛异常。本方法线程安全。

`String` **Decrypt(String padding, String str)**：解密任意长度密文（base64）得到字符串（utf-8），出错抛异常。本方法线程安全。padding指定填充方式，如：PKCS1、OAEP+SHA256大写，参考上面的加密填充方式表格，使用空值时默认为PKCS1。

`byte[]` **Decrypt(String padding, byte[] data)**：解密任意长度数据，出错抛异常。本方法线程安全。

`String` **Sign(String hash, String str)**：对字符串str进行签名，返回base64结果，出错抛异常。本方法线程安全。hash指定签名摘要算法和填充方式，如：SHA256、PSS+SHA1大写，参考上面的签名填充方式表格。

`byte[]` **Sign(String hash, byte[] data)**：对data进行签名，出错抛异常。本方法线程安全。

`boolean` **Verify(String hash, String sign, String str)**：验证字符串str的签名是否是sign（base64），出错抛异常。本方法线程安全。hash指定签名摘要算法和填充方式，如：SHA256、PSS+SHA1大写，参考上面的签名填充方式表格。

`boolean` **Verify(String hash, byte[] sign, byte[] data)**：验证data的签名是否是sign，出错抛异常。本方法线程安全。






[​](?)

[​](?)

## OpenSSL RSA常用命令行参考
``` bat
::先准备一个测试文件 test.txt 里面填少量内容，openssl不支持自动分段加密

::生成新密钥
openssl genrsa -out private.pem 1024

::提取公钥PKCS#8
openssl rsa -in private.pem -pubout -out public.pem

::转换成RSAPublicKey PKCS#1
openssl rsa -pubin -in public.pem -RSAPublicKey_out -out public.pem.rsakey
::测试RSAPublicKey PKCS#1，不出意外会出错。因为这个公钥里面没有OID，通过RSA_PEM转换成PKCS#8自动带上OID就能正常加密
echo abcd123 | openssl rsautl -encrypt -inkey public.pem.rsakey -pubin



::加密和解密，填充方式：PKCS1
openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:pkcs1 -in test.txt -pubin -inkey public.pem -out test.txt.enc.bin
openssl pkeyutl -decrypt -pkeyopt rsa_padding_mode:pkcs1 -in test.txt.enc.bin -inkey private.pem -out test.txt.dec.txt

::加密和解密，填充方式：OAEP+SHA256，掩码生成函数MGF1使用相同的hash算法
openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in test.txt -pubin -inkey public.pem -out test.txt.enc.bin
openssl pkeyutl -decrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in test.txt.enc.bin -inkey private.pem -out test.txt.dec.txt


::命令行参数中的sha256可以换成md5、sha1等；如需sha3系列，就换成sha3-256即可


::签名和验证，填充方式：PKCS1+SHA256
openssl dgst -sha256 -binary -sign private.pem -out test.txt.sign.bin test.txt
openssl dgst -sha256 -binary -verify public.pem -signature test.txt.sign.bin test.txt

::签名和验证，填充方式：PSS+SHA256 ，salt=-1使用hash长度=256/8，掩码生成函数MGF1使用相同的hash算法
openssl dgst -sha256 -binary -out test.txt.hash test.txt
openssl pkeyutl -sign -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -in test.txt.hash -inkey private.pem -out test.txt.sign.bin
openssl pkeyutl -verify -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -in test.txt.hash -pubin -inkey public.pem -sigfile test.txt.sign.bin
```






[​](?)

[​](?)

[​](?)

[​](?)

[​](?)

[​](?)

# :open_book:知识库

请移步到[RSA-csharp](https://github.com/xiangyuecn/RSA-csharp)阅读知识库部分，知识库内包含了详细的PEM格式解析，和部分ASN.1语法；然后逐字节分解PEM字节码教程。

本库的诞生是由于微信付款到银行卡的功能，然后微信提供的RSA公钥接口返回的公钥和openssl -RSAPublicKey_out生成的一样，公钥 PEM 字节码内没有OID（目测是因为不带 OID 所以openssl 自己都不支持用这个公钥来加密数据）,这种是不是PKCS#1 格式不清楚(目测是，大部分文章也说是)，正反都是难用，所以就撸了一个java版转换代码，也不是难事以前撸过C#的，copy C#的代码过来改改就上线使用了。

本库的代码整理未使用IDE，RSA_PEM.java copy过来的，Test.java直接用的文本编辑器编写，*.java文件全部丢到根目录，没有创建包名目录，源码直接根目录裸奔，简单粗暴；这样的项目结构肉眼看去也算是简洁，也方便copy文件使用。


[​](?)

[​](?)

[​](?)

# :star:捐赠
如果这个库有帮助到您，请 Star 一下。

您也可以使用支付宝或微信打赏作者：

![](https://gitee.com/xiangyuecn/Recorder/raw/master/assets/donate-alipay.png)  ![](https://gitee.com/xiangyuecn/Recorder/raw/master/assets/donate-weixin.png)
