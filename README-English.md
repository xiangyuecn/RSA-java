# :open_book:RSA-java Usage Documentation

> This document is translated from Chinese to English using Google Translate.

**Functions of this project: support `PEM` (`PKCS#1`, `PKCS#8`) format RSA key generation, import, and export in `Java` environments; a variety of common RSA encryption signatures padding algorithm support.**

- Support Java8 (1.8) and above
- RSA can be created through `PEM`, `XML` format keys
- RSA can be created by specifying key digits and key parameters
- Can export `PEM`, `XML` format public key, private key; format mutual conversion
- Public key encryption, private key decryption: `NoPadding`, `PKCS1Padding`, `OAEP+MD5`, `OAEP+SHA1 ... SHA3-512`
- Private key signature, public key verification: `PKCS1+SHA1 ... SHA3-512`, `PKCS1+MD5`, `PSS+SHA1 ... SHA3-512`
- Unconventional: private key encryption, public key decryption, public key signature, private key verification
- Multilingual support: provide Chinese and English language support
- There is also a C# version [RSA-csharp](https://github.com/xiangyuecn/RSA-csharp), all encrypted signature algorithms are interoperable in `Java`, `.NET`, `OpenSSL`
- The source code is simple, and compile and test `.bat|.sh` scripts are provided. The source code can be modified and run without IDE, and can be used by copying

[​](?)

You can just copy the `RSA_PEM.java` and `RSA_Util.java` files to your project to use all the functions. You can also clone the entire project code and double-click `Test-Build-Run.bat` to run the test directly (macOS, linux use the terminal to run `.sh`), through the `scripts/Create-jar.bat(sh)` script can generate jar files for project reference.

The underlying implementation of the `RSA_PEM` class uses bytecode parsing of the PEM file at the binary level, which is simple, lightweight, and zero-dependent; `RSA_Util` is a class that encapsulates RSA operations, it supports most encryption signature modes under higher versions of Java. In addition, it can be used with the jar encryption enhancement package of `BouncyCastle` to obtain richer encryption signature mode support.


[​](?)

**Screenshot of Test-Build-Run.bat test compilation and operation:**

![console test](images/1-en.png)


[​](?)

[​](?)

## Quick Start: Encryption, Decryption, Signature, Verification

### Step 1: Reference RSA-java
- Method 1: Copy the `RSA_PEM.java` and `RSA_Util.java` files directly to your project and use them.
- Method 2: Use the `scripts/Create-jar.bat(sh)` script to package and generate a jar, and add this jar package to the project to use it.
- Method 3: Download the jar file in Releases (that is, the jar packaged by the method 2 script), and add this jar package to the project to use it.


### Step 2: Write the code
``` java
//Parse pem or xml first, and both public and private keys can be parsed 
//RSA_PEM pem=RSA_PEM.FromPEM("-----BEGIN XXX KEY-----....-----END XXX KEY-----");
//RSA_PEM pem=RSA_PEM.FromXML("<RSAKeyValue><Modulus>....</RSAKeyValue>");

//Directly create RSA operation classes, which can be created as global objects, and both encryption and decryption signatures support concurrent calls
//RSA_Util rsa=new RSA_Util(pem);
RSA_Util rsa=new RSA_Util(2048); //You can also directly generate a new key, rsa.ToPEM() gets the pem object

//Optionally register BouncyCastle's jar encryption enhancement package (just register once when the program starts), which is used to be compatible with lower versions of Java, and to implement encrypted signature padding methods that Java does not support; go to https://www.bouncycastle.org/latest_releases.html Download bcprov-jdk**-**.jar
//Security.addProvider(new BouncyCastleProvider());
//RSA_Util.UseBouncyCastle(BouncyCastleProvider.PROVIDER_NAME);

//Encrypt with public key, padding mode: PKCS1, you can use OAEP+SHA256 and other padding modes
String enTxt=rsa.Encrypt("PKCS1", "test123");
//Decrypt with private key
String deTxt=rsa.Decrypt("PKCS1", enTxt);

//Sign with private key, padding mode: PKCS1+SHA1, PSS+SHA256 and other padding modes can be used
String sign=rsa.Sign("PKCS1+SHA1", "test123");
//Verify with public key
boolean isVerify=rsa.Verify("PKCS1+SHA1", sign, "test123");

//Export PEM text
String pemTxt=rsa.ToPEM(false).ToPEM_PKCS8(false);

//Unconventional (unsafe, not recommended): private key encryption, public key decryption, public key signature, private key verification
RSA_Util rsaS_Private=rsa.SwapKey_Exponent_D__Unsafe();
RSA_Util rsaS_Public=new RSA_Util(rsa.ToPEM(true)).SwapKey_Exponent_D__Unsafe();
//... rsaS_Private.Encrypt rsaS_Public.Decrypt
//... rsaS_Public.Sign rsaS_Private.Verify

System.out.println(pemTxt+"\n"+enTxt+"\n"+deTxt+"\n"+sign+"\n"+isVerify);
//****For more examples, please read Test.java****
//****For more functional methods, please read the detailed documentation below****
```

**If you need function customization, website, app, small program development, etc., please add the QQ group below and contact the group owner (ie the author), thank you~**



[​](?)

## [QQ group] communication and support

Welcome to join QQ group: 421882406, pure lowercase password: `xiangyuecn`

<img src="https://gitee.com/xiangyuecn/Recorder/raw/master/assets/qq_group_421882406.png" width="220px">






[​](?)

[​](?)

[​](?)

[​](?)

[​](?)

[​](?)

# :open_book:Documentation

## Encryption Paddings

> In the table below, BC is the support of BouncyCastle's jar encryption enhancement package (can be registered through the RSA_Util.UseBouncyCastle method); √ means support, × means no support, and other values ​​are supported by a certain version (Java9); Among them, the mask generation function MGF1 of OAEP uses the same Hash algorithm as OAEP, and the encryption and decryption implementation code uniformly adopts: "RSA/ECB/OAEPPadding" mode + configuration parameters makes Java underlying calls; Java's RSA defaults to PKCS1 padding way (Android defaults to NoPadding?).

Padding|Algorithm|Java|BC
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



## Signature Paddings

> In the table below, BC is the support of BouncyCastle's jar encryption enhancement package (can be registered through the RSA_Util.UseBouncyCastle method); √ means support, × means no support, and other values ​​are supported by a certain version (Java11); Among them, the number of salt bytes of PSS is equal to the number of bytes of the Hash algorithm used, the mask generation function MGF1 of PSS uses the same Hash algorithm as PSS, the value of the tracking attribute TrailerField is fixed at 0xBC, and the signature implementation code uniformly adopts: "RSASSA-PSS" mode + configuration parameters makes Java underlying calls.

Padding|Algorithm|Java|BC
:-|:-|:-:|:-:
SHA1 ... SHA3-512|Same as PKCS1+SHA***||
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

## RSA_PEM Class Documentation
The `RSA_PEM.java` file does not depend on any files, you can directly copy this file to use in your project; through `FromPEM`, `ToPEM` and `FromXML`, `ToXML` two pairs of methods, you can implement PEM `PKCS#1`, `PKCS#8` mutual conversion, PEM, XML mutual conversion.

Note: `openssl rsa -in privateKey -pubout` exports PKCS#8 format public key (used more), `openssl rsa -pubin -in PKCS#8 publicKey -RSAPublicKey_out` exports PKCS#1 format public key (rarely used).


### Static Attributes and Methods

`RSA_PEM` **FromPEM(String pem)**: Create RSA with PEM format key, support PKCS#1, PKCS#8 format PEM, error will throw an exception. pem format such as: `-----BEGIN XXX KEY-----....-----END XXX KEY-----`.

`RSA_PEM` **FromXML(String xml)**: Convert the key in XML format to PEM, support public key xml, private key xml, and an exception will be thrown if an error occurs. xml format such as: `<RSAKeyValue><Modulus>....</RSAKeyValue>`.

`String` **T(String zh, String en)**: Simplified multi-language support, returns Chinese or English according to the current language `Lang()` value.

`String` **Lang()**, **SetLang(String lang)**: Simplified multi-language support, value: `zh` (Simplified Chinese), `en` (English-US), the default value is based on the system, and can be set to the specified language.


### Construction Methods

**RSA_PEM(RSAPublicKey publicKey, RSAPrivateKey privateKeyOrNull)**: Construct a PEM using the public and private keys in RSA. The private key may not be provided, and the exported PEM only contains the public key.

**RSA_PEM(byte[] modulus, byte[] exponent, byte[] d, byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] inverseQ)**: Construct a PEM through the full amount of PEM field parameters. Except for the modulus and public key exponent that must be provided, other private key exponent information must be provided or not provided at all (the exported PEM only contains the public key) Note: all If the first byte of the parameter is 0, it must be removed first.

**RSA_PEM(byte[] modulus, byte[] exponent, byte[] dOrNull)**: Construct a PEM through the public key exponent and the private key exponent, and P and Q will be calculated in reverse, but they are extremely unlikely to be the same as the P and Q of the original generated key. Note: If the first byte of all parameters is 0, it must be removed first. Errors will throw exceptions. The private key exponent may not be provided, and the exported PEM only contains the public key.


### Instance Attributes

`byte[]`: **Key_Modulus**(Modulus n, both public key and private key), **Key_Exponent**(Public key exponent e, both public key and private key), **Key_D**(Private key exponent d, only available when private key); These 3 are enough for encryption and decryption.

`byte[]`: **Val_P**(prime1), **Val_Q**(prime2), **Val_DP**(exponent1), **Val_DQ**(exponent2), **Val_InverseQ**(coefficient); The private key in PEM has more values; these values can be deduced through n, e, and d (only the effective value is deduced, which is different from the original value with high probability).

`int` **keySize()**: Key digits.

`boolean` **hasPrivate()**: Whether to include the private key.


### Instance Methods

`RSAPublicKey` **getRSAPublicKey()**: Get the public key Java object.

`RSAPrivateKey` **getRSAPrivateKey()**: Get the private key Java object. If the PEM does not contain the private key, an error will be reported directly.

`RSA_PEM` **CopyToNew(boolean convertToPublic)**: Copy the key in the current PEM to a new PEM object. convertToPublic: When equal to true, the PEM containing the private key will only return the public key, and the PEM containing only the public key will not be affected.

`RSA_PEM` **SwapKey_Exponent_D__Unsafe()**: [Unsafe and not recommended] Swap the public key exponent (Key_Exponent) and the private key exponent (Key_D): use the public key as the private key (new.Key_D=this.Key_Exponent) and the private key as the public key (new.Key_Exponent=this.Key_D), returns a new PEM object; for example, used for: private key encryption, public key decryption, this is an unconventional usage. The current object must contain a private key, otherwise an exception will be thrown if it cannot be swapped. Note: It is very insecure to use the public key as a private key, because the public key exponent of most generated keys is 0x10001 (AQAB), which is too easy to guess and cannot be used as a real private key.

`byte[]` **ToDER(boolean convertToPublic, boolean privateUsePKCS8, boolean publicUsePKCS8)**: Convert the key pair in RSA to DER format. The DER format is binary data before Base64 text encoding in PEM. Refer to the ToPEM method for parameter meanings.

`String` **ToPEM(boolean convertToPublic, boolean privateUsePKCS8, boolean publicUsePKCS8)**: Convert the key in RSA to PEM format. convertToPublic: When it is equal to true, the RSA containing the private key will only return the public key, and the RSA containing only the public key will not be affected. **privateUsePKCS8**: The return format of the private key, when it is equal to true, it returns the PKCS#8 format (`-----BEGIN PRIVATE KEY-----`), otherwise returns PKCS#1 format (`-----BEGIN RSA PRIVATE KEY-----`), this parameter is invalid when returning a public key; Both formats are used more commonly. **publicUsePKCS8**: The return format of the public key, when it is equal to true, it returns the PKCS#8 format (`-----BEGIN PUBLIC KEY-----`), otherwise returns PKCS#1 format (`-----BEGIN RSA PUBLIC KEY-----`), this parameter is invalid when returning the private key; Generally, the true PKCS#8 format public key is mostly used, and the PKCS#1 format public key seems to be relatively rare.

`String` **ToPEM_PKCS1(boolean convertToPublic)**: Simplified writing of the ToPEM method, regardless of the public key or the private key, it returns the PKCS#1 format; it seems that the export of the PKCS#1 public key is less used, and the PKCS#8 public key is used more, and the private key #1#8 is almost.

`String` **ToPEM_PKCS8(boolean convertToPublic)**: Simplified writing of the ToPEM method, regardless of whether the public key or the private key returns the PKCS#8 format.

`String` **ToXML(boolean convertToPublic)**: Convert the key in RSA to XML format. If convertToPublic, the RSA containing the private key will only return the public key, and the RSA containing only the public key will not be affected.




[​](?)

[​](?)

## RSA_Util Class Documentation
The `RSA_Util.java` file depends on `RSA_PEM.java`, which encapsulates encryption, decryption, signature, verification, and key import and export operations.


### Static Attributes and Methods

`String` **RSAPadding_Enc(String padding)**: Convert the encryption padding into the corresponding Algorithm string, such as: `PKCS1 -> RSA/ECB/PKCS1Padding`.

`String` **RSAPadding_Sign(String hash)**: Convert the signature padding into the corresponding Algorithm string, such as: `PKCS1+SHA1 -> SHA1withRSA`.

`boolean` **IsJavaLowVerSupportError(Throwable err)**: Determine whether the exception message is an error caused by low version Java compatibility.

`void` **UseBouncyCastle(String providerName)**: Forces the use of BouncyCastle's jar encryption enhancement package for RSA operations. You only need to call it once after the program starts, you need to call `Security.addProvider(new BouncyCastleProvider())` to register globally first, and then call this method to enable: `UseBouncyCastle(BouncyCastleProvider.PROVIDER_NAME)`, pass in null to cancel enabled. Introduce the BouncyCastle encryption enhancement package into the project to expand the Java encryption function, first go to https://www.bouncycastle.org/latest_releases.html to download bcprov-jdk**-**.jar, and call this method to register when the program starts And enable it to get support for all encrypted signature padding methods.

`boolean` **IsUseBouncyCastle()**: Whether to force the use of BouncyCastle's jar encryption enhancement package for RSA operations. When true, Java's RSA implementation will not be used.


### Construction Methods

**RSA_Util(int keySize)**: Create a new RSA with the specified key size, a new key will be generated, and an exception will be thrown if an error occurs.

**RSA_Util(String pemOrXML)**: Create an RSA with a key in `PEM` or `XML` format, which can be a public key or a private key, and throws an exception if an error occurs. XML format such as: `<RSAKeyValue><Modulus>...</RSAKeyValue>`. pem supports `PKCS#1`, `PKCS#8` format, the format is as follows: `-----BEGIN XXX KEY-----....-----END XXX KEY-----`.

**RSA_Util(RSA_PEM pem)**: Create RSA through a pem object, where pem is a public key or private key, and an exception is thrown if an error occurs.


### Instance Attributes

`RSAPublicKey` **publicKey**: RSA public key.

`RSAPrivateKey` **privateKey**: RSA private key, null if there is only public key.

`int` **keySize()**: Key digits.

`boolean` **hasPrivate()**: Whether to include the private key.


### Instance Methods

`String` **ToXML(boolean convertToPublic)**: Export the secret key in XML format. If the RSA contains a private key, the private key will be exported by default. When only the public key is set, only the public key will be exported; if the private key is not included, only the public key will be exported.

`RSA_PEM` **ToPEM(boolean convertToPublic)**: Export RSA_PEM object (then you can export PEM text by RSA_PEM.ToPEM method), if convertToPublic RSA containing private key will only return public key, RSA containing only public key will not be affected.

`RSA_Util` **SwapKey_Exponent_D__Unsafe()**: [Unsafe and not recommended] Swap the public key exponent (Key_Exponent) and the private key exponent (Key_D): use the public key as the private key (new.Key_D=this.Key_Exponent) and the private key as the public key (new.Key_Exponent=this.Key_D), returns a new RSA object; for example, used for: private key encryption, public key decryption, this is an unconventional usage. If the current key is a public key, the swap will not occur, and the new RSA returned will allow decryption and signing operations with the public key. Note: It is very unsafe to use a public key as a private key, because the public key exponent of most generated keys is 0x10001 (AQAB), which is too easy to guess and cannot be used as a true private key. In some private key encryption implementations, such as Java's own RSA, when using non-NoPadding padding, encryption with private key objects may use EMSA-PKCS1-v1_5 padding (using the private key exponent to construct a public key object does not have this problem ), so when interoperating between different programs, you may need to use the corresponding padding algorithm to first fill the data, and then use NoPadding padding to encrypt (decryption also uses NoPadding padding to decrypt, and then remove the padding data).

`String` **Encrypt(String padding, String str)**: Encrypt arbitrary length string (utf-8) returns base64, and an exception is thrown if an error occurs. This method is thread safe. padding specifies the encryption padding, such as: PKCS1, OAEP+SHA256 uppercase, refer to the encryption padding table above, and the default is PKCS1 when using a null value.

`byte[]` **Encrypt(String padding, byte[] data)**: Encrypt arbitrary length data, and throw an exception if an error occurs. This method is thread safe.

`String` **Decrypt(String padding, String str)**: Decrypt arbitrary length ciphertext (base64) to get string (utf-8), and throw an exception if an error occurs. This method is thread safe. padding specifies the encryption padding, such as: PKCS1, OAEP+SHA256 uppercase, refer to the encryption padding table above, and the default is PKCS1 when using a null value.

`byte[]` **Decrypt(String padding, byte[] data)**: Decrypt arbitrary length data, and throw an exception if an error occurs. This method is thread safe.

`String` **Sign(String hash, String str)**: Sign the string str, return the base64 result, and throw an exception if an error occurs. This method is thread safe. hash specifies the signature digest algorithm and signature padding, such as: SHA256, PSS+SHA1 uppercase, refer to the signature padding table above.

`byte[]` **Sign(String hash, byte[] data)**: Sign the data, and throw an exception if an error occurs. This method is thread safe.

`boolean` **Verify(String hash, String sign, String str)**: Verify whether the signature of the string str is sign (base64), and throw an exception if an error occurs. This method is thread safe. hash specifies the signature digest algorithm and signature padding, such as: SHA256, PSS+SHA1 uppercase, refer to the signature padding table above.

`boolean` **Verify(String hash, byte[] sign, byte[] data)**: Verify whether the signature of data is sign, and throw an exception if an error occurs. This method is thread safe.






[​](?)

[​](?)

## OpenSSL RSA common command line reference
``` bat
::First prepare a test file test.txt and fill in a small amount of content, openssl does not support automatic segmentation encryption

::Generate new key
openssl genrsa -out private.pem 1024

::Extract public key PKCS#8
openssl rsa -in private.pem -pubout -out public.pem

::Convert to RSAPublicKey PKCS#1
openssl rsa -pubin -in public.pem -RSAPublicKey_out -out public.pem.rsakey
::Test RSAPublicKey PKCS#1, no accident will go wrong. Because there is no OID in this public key, it can be encrypted normally by converting RSA_PEM into PKCS#8 and automatically bringing OID
echo abcd123 | openssl rsautl -encrypt -inkey public.pem.rsakey -pubin



::Encryption and decryption, padding mode: PKCS1
openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:pkcs1 -in test.txt -pubin -inkey public.pem -out test.txt.enc.bin
openssl pkeyutl -decrypt -pkeyopt rsa_padding_mode:pkcs1 -in test.txt.enc.bin -inkey private.pem -out test.txt.dec.txt

::Encryption and decryption, padding mode: OAEP+SHA256, mask generation function MGF1 uses the same hash algorithm
openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in test.txt -pubin -inkey public.pem -out test.txt.enc.bin
openssl pkeyutl -decrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in test.txt.enc.bin -inkey private.pem -out test.txt.dec.txt


::The sha256 in the command line parameters can be replaced by md5, sha1, etc.; if you need the sha3 series, you can replace it with sha3-256


::Signature and verification, padding mode: PKCS1+SHA256
openssl dgst -sha256 -binary -sign private.pem -out test.txt.sign.bin test.txt
openssl dgst -sha256 -binary -verify public.pem -signature test.txt.sign.bin test.txt

::Signature and verification, padding mode: PSS+SHA256, salt=-1 use hash length=256/8, mask generation function MGF1 uses the same hash algorithm
openssl dgst -sha256 -binary -out test.txt.hash test.txt
openssl pkeyutl -sign -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -in test.txt.hash -inkey private.pem -out test.txt.sign.bin
openssl pkeyutl -verify -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -in test.txt.hash -pubin -inkey public.pem -sigfile test.txt.sign.bin
```







[​](?)

[​](?)

[​](?)

# :star:Donate
If this library is helpful to you, please star it.

You can also use Alipay or WeChat to donate to the author:

![](https://gitee.com/xiangyuecn/Recorder/raw/master/assets/donate-alipay.png)  ![](https://gitee.com/xiangyuecn/Recorder/raw/master/assets/donate-weixin.png)

