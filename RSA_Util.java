package com.github.xiangyuecn.rsajava;

import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;


/**
 * RSA操作封装
 * 
 * GitHub:https://github.com/xiangyuecn/RSA-java
 */
public class RSA_Util {
	/**
	 * 导出XML格式密钥，如果convertToPublic含私钥的RSA将只返回公钥，仅含公钥的RSA不受影响
	 */
	public String ToXML(boolean convertToPublic) {
		return ToPEM(convertToPublic).ToXML(convertToPublic);
	}
	/**
	 * 将密钥导出成PEM对象，如果convertToPublic含私钥的RSA将只返回公钥，仅含公钥的RSA不受影响
	 */
	public RSA_PEM ToPEM(boolean convertToPublic) {
		return new RSA_PEM(publicKey, convertToPublic?null:privateKey);
	}
	/***
	 * 【不安全、不建议使用】对调交换公钥指数（Key_Exponent）和私钥指数（Key_D）：把公钥当私钥使用（new.Key_D=this.Key_Exponent）、私钥当公钥使用（new.Key_Exponent=this.Key_D），返回一个新RSA对象；比如用于：私钥加密、公钥解密，这是非常规的用法
	 * 。当前对象必须含私钥，否则无法交换会直接抛异常
	 * 。注意：把公钥当私钥使用是非常不安全的，因为绝大部分生成的密钥的公钥指数为 0x10001（AQAB），太容易被猜测到，无法作为真正意义上的私钥
	 */
	public RSA_Util SwapKey_Exponent_D__Unsafe() throws Exception {
		return new RSA_Util(ToPEM(false).SwapKey_Exponent_D__Unsafe());
	}
	
	
	
	/** 内置加密解密填充方式列表 **/
	static public String[] RSAPadding_Enc_DefaultKeys() {
		String s="NO, PKCS1";
		s+=", OAEP+SHA1, OAEP+SHA256, OAEP+SHA224, OAEP+SHA384, OAEP+SHA512";
		s+=", OAEP+SHA-512/224, OAEP+SHA-512/256";
		s+=", OAEP+SHA3-256, OAEP+SHA3-224, OAEP+SHA3-384, OAEP+SHA3-512";
		s+=", OAEP+MD5";
		return s.split(", ");
	}
	/**
	 * 将填充方式转换成Java Cipher支持的RSA加密解密填充模式，padding取值和对应的填充模式：
	 * <pre>
	 * null: 等同于PKCS1
	 *   "": 等同于PKCS1
	 *  RSA: 等同于PKCS1
	 * PKCS: 等同于PKCS1
	 *  RAW: 等同于NO
	 * OAEP: 等同于OAEP+SHA1
	 * RSA/ECB/OAEPPadding: 等同于OAEP+SHA1
	 * 
	 *    NO: RSA/ECB/NoPadding
	 * PKCS1: RSA/ECB/PKCS1Padding （默认值，等同于"RSA"）
	 * OAEP+SHA1  : RSA/ECB/OAEPwithSHA-1andMGF1Padding
	 * OAEP+SHA256: RSA/ECB/OAEPwithSHA-256andMGF1Padding
	 * OAEP+SHA224: RSA/ECB/OAEPwithSHA-224andMGF1Padding
	 * OAEP+SHA384: RSA/ECB/OAEPwithSHA-384andMGF1Padding
	 * OAEP+SHA512: RSA/ECB/OAEPwithSHA-512andMGF1Padding
	 * OAEP+SHA-512/224: RSA/ECB/OAEPwithSHA-512/224andMGF1Padding （SHA-512/*** 2012年发布）
	 * OAEP+SHA-512/256: RSA/ECB/OAEPwithSHA-512/256andMGF1Padding
	 * OAEP+SHA3-256: RSA/ECB/OAEPwithSHA3-256andMGF1Padding （SHA3-*** 2015年发布）
	 * OAEP+SHA3-224: RSA/ECB/OAEPwithSHA3-224andMGF1Padding
	 * OAEP+SHA3-384: RSA/ECB/OAEPwithSHA3-384andMGF1Padding
	 * OAEP+SHA3-512: RSA/ECB/OAEPwithSHA3-512andMGF1Padding
	 * OAEP+MD5     : RSA/ECB/OAEPwithMD5andMGF1Padding
	 * 
	 * 如果padding包含RSA字符串，将原样返回此值，用于提供Java支持的任何值
	 * 非以上取值，将会抛异常
	 * 
	 * 其中OAEP的掩码生成函数MGF1使用和OAEP相同的Hash算法，加密解密实现代码中统一采用："RSA/ECB/OAEPPadding"模式+配置参数 这种形式进行Java底层调用
	 * 
	 * 以上填充模式全部可用于BouncyCastle的RSA实现；但如果是使用的Java自带的RSA实现，将会有部分模式无法支持：SHA-512/256、SHA-512/224、SHA3，这三种需要Java9以上才支持
	 * 
	 * 参考:
	 * https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
	 * https://docs.oracle.com/en/java/javase/20/docs/specs/security/standard-names.html
	 * https://developer.android.google.cn/reference/javax/crypto/Cipher
	 * </pre>
	 */
	static public String RSAPadding_Enc(String padding) {
		String val=padding;
		if(val==null || val.length()==0) val="PKCS1";
		val=val.toUpperCase();
		
		if("RSA".equals(val) || "PKCS".equals(val)) val="PKCS1";
		if("OAEP".equals(val) || val.endsWith("/OAEPPADDING")) val="OAEP+SHA1";
		if("RAW".equals(val)) val="NO";
		if(val.indexOf("RSA")!=-1) return padding;
		
		switch(val) {
		case "PKCS1": return "RSA/ECB/PKCS1Padding";
		case "NO":    return "RSA/ECB/NoPadding";
		}
		if(val.startsWith("OAEP+")) {
			val=val.replace("OAEP+", "");
			switch(val) {
			case "SHA1":case "SHA256":case "SHA224":case "SHA384":case "SHA512":
			case "SHA512/224":case "SHA512/256":
				val="SHA-"+val.substring(3);
			}
			switch(val) {
			case "SHA-1":case "SHA-256":case "SHA-224":case "SHA-384":case "SHA-512":
			case "SHA3-256":case "SHA3-224":case "SHA3-384":case "SHA3-512":
			case "SHA-512/224":case "SHA-512/256":case "MD5":
				return "RSA/ECB/OAEPwith"+val+"andMGF1Padding";
			}
		}
		throw new RuntimeException(T("RSAPadding_Enc未定义Padding: ", "RSAPadding_Enc does not define Padding: ")+padding);
	}
	
	/** 内置签名填充方式列表 **/
	static public String[] RSAPadding_Sign_DefaultKeys() {
		String s="PKCS1+SHA1, PKCS1+SHA256, PKCS1+SHA224, PKCS1+SHA384, PKCS1+SHA512";
		s+=", PKCS1+SHA-512/224, PKCS1+SHA-512/256";
		s+=", PKCS1+SHA3-256, PKCS1+SHA3-224, PKCS1+SHA3-384, PKCS1+SHA3-512";
		s+=", PKCS1+MD5";
		s+=", PSS+SHA1, PSS+SHA256, PSS+SHA224, PSS+SHA384, PSS+SHA512";
		s+=", PSS+SHA-512/224, PSS+SHA-512/256";
		s+=", PSS+SHA3-256, PSS+SHA3-224, PSS+SHA3-384, PSS+SHA3-512";
		s+=", PSS+MD5";
		return s.split(", ");
	}
	/**
	 * 将填充方式转换成Java Signature支持的RSA签名填充模式，hash取值和对应的填充模式：
	 * <pre>
	 * SHA*** : 等同于PKCS1+SHA***，比如"SHA256" == "PKCS1+SHA256"
	 * MD5    : 等同于PKCS1+MD5
	 * RSASSA-PSS: 等同于PSS+SHA1
	 * 
	 * PKCS1+SHA1  : SHA1withRSA
	 * PKCS1+SHA256: SHA256withRSA
	 * PKCS1+SHA224: SHA224withRSA
	 * PKCS1+SHA384: SHA384withRSA
	 * PKCS1+SHA512: SHA512withRSA
	 * PKCS1+SHA-512/224: SHA512/224withRSA （SHA-512/*** 2012年发布）
	 * PKCS1+SHA-512/256: SHA512/256withRSA
	 * PKCS1+SHA3-256: SHA3-256withRSA （SHA3-*** 2015年发布）
	 * PKCS1+SHA3-224: SHA3-224withRSA
	 * PKCS1+SHA3-384: SHA3-384withRSA
	 * PKCS1+SHA3-512: SHA3-512withRSA
	 * PKCS1+MD5   : MD5withRSA
	 * 
	 * PSS+SHA1  : SHA1withRSA/PSS
	 * PSS+SHA256: SHA256withRSA/PSS
	 * PSS+SHA224: SHA224withRSA/PSS
	 * PSS+SHA384: SHA384withRSA/PSS
	 * PSS+SHA512: SHA512withRSA/PSS
	 * PSS+SHA-512/224: SHA512/224withRSA/PSS （SHA-512/*** 2012年发布）
	 * PSS+SHA-512/256: SHA512/256withRSA/PSS
	 * PSS+SHA3-256: SHA3-256withRSA/PSS （SHA3-*** 2015年发布）
	 * PSS+SHA3-224: SHA3-224withRSA/PSS
	 * PSS+SHA3-384: SHA3-384withRSA/PSS
	 * PSS+SHA3-512: SHA3-512withRSA/PSS
	 * PSS+MD5   : MD5withRSA/PSS （此方式不同实现下不一定支持）
	 * 
	 * 如果hash包含RSA字符串，将原样返回此值，用于提供Java支持的任何值
	 * 非以上取值，将会抛异常
	 * 
	 * 其中PSS的salt字节数等于使用的Hash算法字节数，PSS的掩码生成函数MGF1使用和PSS相同的Hash算法，跟踪属性TrailerField取值固定为0xBC（PSSParameterSpec.TRAILER_FIELD_BC），签名实现代码中统一采用："RSASSA-PSS"模式+配置参数 这种形式进行Java底层调用
	 * 
	 * 以上填充模式全部可用于BouncyCastle的RSA实现；但如果是使用的Java自带的RSA实现，将会有部分模式无法支持：所有PSS模式需要Java11以上才支持，SHA-512/256、SHA-512/224需要需要Java11以上，SHA3需要Java16以上
	 * 
	 * 参考:
	 * https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
	 * https://docs.oracle.com/en/java/javase/20/docs/specs/security/standard-names.html
	 * https://developer.android.google.cn/reference/java/security/Signature
	 * </pre>
	 */
	static public String RSAPadding_Sign(String hash) {
		String val=hash==null?"":hash;
		val=val.toUpperCase();
		
		if("RSASSA-PSS".equals(val)) val="PSS+SHA1";
		if(val.indexOf("RSA")!=-1) return hash;
		
		String pss="";
		if(val.startsWith("PSS+")) {
			val=val.substring(4);
			pss="/PSS";
		}else if(val.startsWith("PKCS1+")) {
			val=val.substring(6);
		}
		switch(val) {
		case "SHA-1":case "SHA-256":case "SHA-224":case "SHA-384":case "SHA-512":
		case "SHA-512/224":case "SHA-512/256":
			val=val.replace("-", "");
		}
		switch(val) {
		case "SHA1":case "SHA256":case "SHA224":case "SHA384":case "SHA512":
		case "SHA3-256":case "SHA3-224":case "SHA3-384":case "SHA3-512":
		case "SHA512/224":case "SHA512/256":case "MD5":
			return val+"withRSA"+pss;
		}
		throw new RuntimeException(T("RSAPadding_Sign未定义Hash: ", "RSAPadding_Sign does not define Hash: ")+hash);
	}
	
	static private String JavaLowVerSupportMsg(String tag) {
		return T("低版本的Java不支持"+tag+"，解决办法1：升级使用高版本Java；解决办法2：引入BouncyCastle的jar加密增强包来兼容低版本Java，可到 https://www.bouncycastle.org/latest_releases.html 下载 bcprov-jdk**-**.jar，然后在程序启动时调用"+Msg_Bc_Reg+"进行注册即可得到全部支持。", "The lower version of Java does not support "+tag+". Solution 1: Upgrade to a higher version of Java; Solution 2: Introduce BouncyCastle's jar encryption enhancement package to be compatible with the lower version of Java, you can download bcprov-jdk**-**.jar from https://www.bouncycastle.org/latest_releases.html, and then call"+Msg_Bc_Reg+"to register when the program starts to get full support.");
	}
	static private final String Msg_Bc_Reg=" `Security.addProvider(new BouncyCastleProvider()) + RSA_Util.UseBouncyCastle(BouncyCastleProvider.PROVIDER_NAME)` ";
	/** 是否是因为低版本Java兼容性产生的错误 **/
	static public boolean IsJavaLowVerSupportError(Throwable err) {
		Throwable e=err;
		while(e!=null) {
			if(e.getMessage().contains(Msg_Bc_Reg)) {
				return true;
			}
			e=e.getCause();
		}
		return false;
	}
	static private void checkSHA3Support() {
		try {
			MessageDigest.getInstance("SHA3-256");
		}catch(Exception e) {
			throw new RuntimeException(JavaLowVerSupportMsg(T("SHA3系列摘要算法","SHA3 series digest algorithm")));
		}
	}
	static private void checkSHA512xSupport(String hash) {
		try {
			MessageDigest.getInstance(hash);
		}catch(Exception e) {
			throw new RuntimeException(JavaLowVerSupportMsg(hash+T("摘要算法"," Digest Algorithm")));
		}
	}
	/** 简版多语言支持，根据当前语言返回中文或英文，简化调用{@link RSA_PEM#T(String, String)} **/
	static private String T(String zh, String en) {
		return RSA_PEM.T(zh, en);
	}
	
	
	
	
	/**
	 * 加密任意长度字符串（utf-8）返回base64，出错抛异常。本方法线程安全。padding指定填充方式（如：PKCS1、OAEP+SHA256大写），使用空值时默认为PKCS1，取值参考{@link #RSAPadding_Enc}
	 */
	public String Encrypt(String padding, String str) throws Exception {
		return Base64.getEncoder().encodeToString(Encrypt(padding,str.getBytes("utf-8")));
	}
	/**
	 * 加密任意长度数据，出错抛异常。本方法线程安全。padding指定填充方式（如：PKCS1、OAEP+SHA256大写），使用空值时默认为PKCS1，取值参考{@link #RSAPadding_Enc}
	 */
	public byte[] Encrypt(String padding, byte[] data) throws Exception {
		try(ByteArrayOutputStream stream=new ByteArrayOutputStream()){
			String ctype=RSAPadding_Enc(padding),CType=ctype.toUpperCase();
			
			AlgorithmParameterSpec[] param=null;
			int blockLen = keySize / 8;
			if(CType.indexOf("OAEP")!=-1) {
				//OAEP填充占用 2*hashLen+2 字节：https://www.rfc-editor.org/rfc/rfc8017.html#section-7.1.1
				String[] outType=new String[] { "" };
				int[] outLen=new int[] {0};
				param=createOaepParam(ctype,outType,outLen);
				
				int shaLen=outLen[0];
				int sub=2 * shaLen/8 + 2;
				blockLen -= sub;
				if(blockLen<1) {
					String min="NaN"; if(sub>0) min=(int)Math.pow(2, Math.ceil(Math.log(sub*8)/Math.log(2)))+"";
					throw new RuntimeException("RSA["+ctype+"][keySize="+keySize+"] "+T("密钥位数不能小于", "Key digits cannot be less than ")+min);
				}
				ctype=outType[0];
			} else if(CType.indexOf("NOPADDING")!=-1) {
				//NOOP 无填充，不够数量时会在开头给0
			} else {
				//PKCS1填充占用11字节：https://www.rfc-editor.org/rfc/rfc8017.html#section-7.2.1
				blockLen -= 11;
			}
			Cipher enc=Cipher_getInstance(true, ctype, param);
			
			int start=0;
			while(start<data.length) {
				int len=blockLen;
				if(start+len>data.length) {
					len=data.length-start;
				}
				
				byte[] en = enc.doFinal(data, start, len);
				stream.write(en);
				start+=len;
			}
			
			return stream.toByteArray();
		}
	}
	/**
	 * 解密任意长度密文（base64）得到字符串（utf-8），出错抛异常。本方法线程安全。padding指定填充方式（如：PKCS1、OAEP+SHA256大写），使用空值时默认为PKCS1，取值参考{@link #RSAPadding_Enc}
	 */
	public String Decrypt(String padding, String str) throws Exception {
		if (str==null || str.length()==0) {
			return "";
		}
		byte[] byts = Base64.getDecoder().decode(str);
		byte[] val = Decrypt(padding,byts);
		return new String(val, "utf-8");
	}
	/**
	 * 解密任意长度数据，出错抛异常。本方法线程安全。padding指定填充方式（如：PKCS1、OAEP+SHA256大写），使用空值时默认为PKCS1，取值参考{@link #RSAPadding_Enc}
	 */
	public byte[] Decrypt(String padding, byte[] data) throws Exception {
		try(ByteArrayOutputStream stream=new ByteArrayOutputStream()){
			String ctype=RSAPadding_Enc(padding),CType=ctype.toUpperCase();
			
			AlgorithmParameterSpec[] param=null;
			if(CType.indexOf("OAEP")!=-1) {
				String[] outType=new String[] { "" };
				param=createOaepParam(ctype, outType, new int[1]);
				ctype=outType[0];
			}
			Cipher dec=Cipher_getInstance(false, ctype, param);
			
			int blockLen = keySize / 8;
			int start=0;
			while(start<data.length) {
				int len=blockLen; boolean isEnd=false;
				if(start+len>=data.length) {
					len=data.length-start;
					isEnd=true;
				}
				
				byte[] de = dec.doFinal(data, start, len);
				if(isEnd && CType.indexOf("NOPADDING")!=-1) {
					//没有填充时，去掉开头的0
					int idx=0;
					for(;idx<de.length;idx++) {
						if(de[idx]!=0) break;
					}
					byte[] de2=new byte[de.length-idx];
					System.arraycopy(de, idx, de2, 0, de2.length);
					de=de2;
				}
				stream.write(de);
				start+=len;
			}
			
			return stream.toByteArray();
		}
	}

	private Cipher Cipher_getInstance(boolean enc, String ctype, AlgorithmParameterSpec[] params)  throws Exception {
		int mode=enc?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE;
		Key key=enc?publicKey:privateKey;
		Cipher dec;
		
		if(BcProvider!=null) {
			dec=Cipher.getInstance(ctype, BcProvider);
		}else {
			dec=Cipher.getInstance(ctype);
		}
		if(params!=null) {
			try {
				dec.init(mode, key, params[0]);
			}catch(Exception e) {
				if(params[1]!=null) {//使用候选参数
					dec.init(mode, key, params[1]);
				}else {
					throw e;
				}
			}
		}else {
			dec.init(mode, key);
		}
		return dec;
	}
	static private Pattern OAEP_Exp=Pattern.compile("^RSA/(.+?)/OAEPWITHSHA(3-|-?512/)?[\\-/]?(\\d+)ANDMGF1PADDING$");
	static private OAEPParameterSpec[] createOaepParam(String ctype, String[] outType, int[] outLen) {
		String CType=ctype.toUpperCase(); boolean isMd5=false;
		if(CType.indexOf("MD5")!=-1) {
			isMd5=true; CType=CType.replace("MD5", "SHA-128");//伪装成SHA简化逻辑
		}
		Matcher m=OAEP_Exp.matcher(CType);
		if(!m.find()) {
			throw new RuntimeException(ctype+T("不在预定义列表内，无法识别出Hash算法", " is not in the predefined list, and the Hash algorithm cannot be recognized"));
		}
		int shaN=Integer.parseInt(m.group(3));
		outLen[0]=shaN==1?160:shaN;//sha1 为 160位
		outType[0]="RSA/"+m.group(1)+"/OAEPPadding";

		String hash;
		if(isMd5) {
			hash="MD5";
		}else {
			hash="SHA-"+shaN; String m2=m.group(2);
			if(m2!=null&&m2.length()!=0) {
				if(m2.indexOf("512")!=-1) {
					hash="SHA-512/"+shaN;
				}else {
					hash="SHA3-"+shaN;
				}
			}
			if(BcProvider==null) {
				if(hash.startsWith("SHA3-")) {
					checkSHA3Support();
				}
				if(hash.startsWith("SHA-512/")) {
					checkSHA512xSupport(hash);
				}
			}
		}
		
		OAEPParameterSpec[] arr=new OAEPParameterSpec[2];
		if(hash.startsWith("SHA-512/")) {
			String hash2="SHA-512("+shaN+")";//BouncyCastle支持带括号的
			arr[1]=new OAEPParameterSpec(hash2, "MGF1", new MGF1ParameterSpec(hash2), PSource.PSpecified.DEFAULT);
		}
		arr[0]=new OAEPParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash), PSource.PSpecified.DEFAULT);
		return arr;
	}
	
	
	
	
	/**
	 * 对字符串str进行签名，返回base64结果，出错抛异常。本方法线程安全。hash指定签名摘要算法和填充方式（如：SHA256、PSS+SHA1大写），取值参考{@link #RSAPadding_Sign}
	 */
	public String Sign(String hash, String str) throws Exception {
		return Base64.getEncoder().encodeToString(Sign(hash, str.getBytes("utf-8")));
	}
	/**
	 * 对data进行签名，出错抛异常。本方法线程安全。hash指定签名摘要算法和填充方式（如：SHA256、PSS+SHA1大写），取值参考{@link #RSAPadding_Sign}
	 */
	public byte[] Sign(String hash, byte[] data) throws Exception {
		Signature signature=Signature_getInstance(hash);
		signature.initSign(privateKey);
		signature.update(data);
		return signature.sign();
	}
	/**
	 * 验证字符串str的签名是否是sign（base64），出错抛异常。本方法线程安全。hash指定签名摘要算法和填充方式（如：SHA256、PSS+SHA1大写），取值参考{@link #RSAPadding_Sign}
	 */
	public boolean Verify(String hash, String sign, String str) throws Exception {
		byte[] byts = Base64.getDecoder().decode(sign);
		return Verify(hash, byts, str.getBytes("utf-8"));
	}
	/**
	 * 验证data的签名是否是sign，出错抛异常。本方法线程安全。hash指定签名摘要算法和填充方式（如：SHA256、PSS+SHA1大写），取值参考{@link #RSAPadding_Sign}
	 */
	public boolean Verify(String hash, byte[] sign, byte[] data) throws Exception {
		Signature signVerify=Signature_getInstance(hash);
		signVerify.initVerify(publicKey);
		signVerify.update(data);
		return signVerify.verify(sign);
	}
	
	static private Pattern PSS_Exp=Pattern.compile("^SHA(3-|-?512/)?[\\-/]?(\\d+)WITHRSA/PSS$");
	static private Signature Signature_getInstance(String hashType) throws Exception {
		String stype=RSAPadding_Sign(hashType),SType=stype.toUpperCase();
		Signature val=null;
		boolean isPss=false,is512x=false;
		if(SType.indexOf("SHA3-")!=-1) {
			if(BcProvider==null) checkSHA3Support();
		}
		if(SType.indexOf("512/2")!=-1) {
			is512x=true;
			if(BcProvider==null) checkSHA512xSupport("SHA-512/"+(SType.indexOf("224")!=-1?"224":"256"));
		}
		
		AlgorithmParameterSpec param=null,param2=null;
		if(SType.endsWith("/PSS")) { //转成RSASSA-PSS 然后提供参数
			boolean isMd5=false;
			if(SType.indexOf("MD5")!=-1) {
				isMd5=true; SType=SType.replace("MD5", "SHA-128");//伪装成SHA简化逻辑
			}
			Matcher m=PSS_Exp.matcher(SType);
			if(!m.find()) {
				throw new Exception(stype+T("不在预定义列表内，无法识别出Hash算法", " is not in the predefined list, and the Hash algorithm cannot be recognized"));
			}
			int shaN=Integer.parseInt(m.group(2));
			
			int shaLen=shaN==1?160:shaN;//sha1 为 160位
			stype="RSASSA-PSS"; isPss=true;
			
			String hash;
			if(isMd5) {
				hash="MD5";
			}else {
				hash="SHA-"+shaN; String m2=m.group(1);
				if(m2!=null&&m2.length()!=0) {
					if(m2.indexOf("512")!=-1) {
						hash="SHA-512/"+shaN;
						
						String hash2="SHA-512("+shaN+")";//BouncyCastle支持带括号的
						param2=new PSSParameterSpec(hash2, "MGF1", new MGF1ParameterSpec(hash2), shaLen/8, 1);
					}else {
						hash="SHA3-"+shaN;
					}
				}
			}
			param=new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash), shaLen/8, 1);
		} else if(is512x) {
			try {
				if(BcProvider!=null) {
					val = Signature.getInstance(stype,BcProvider);
				}else {
					val = Signature.getInstance(stype);
				}
			}catch(Exception e) { }
			if(val==null) {//BouncyCastle支持带括号的
				String t2=stype.replace("/224", "(224)").replace("/256", "(256)");
				try {
					if(BcProvider!=null) {
						val = Signature.getInstance(t2,BcProvider);
					}else {
						val = Signature.getInstance(t2);
					}
				}catch(Exception e) { }
			}
		}
		
		if(val==null) {
			if(BcProvider!=null) {
				val=Signature.getInstance(stype,BcProvider);
			}else {
				try {
					val=Signature.getInstance(stype);
				}catch(Exception e) {
					if(isPss) {
						throw new RuntimeException(JavaLowVerSupportMsg("RSASSA-PSS"+T("签名填充模式", " signature padding mode")),e);
					}
					throw e;
				}
			}
		}
		if(param!=null) {
			try {
				val.setParameter(param);
			}catch(Exception e) {
				if(param2!=null) { //使用候选参数
					val.setParameter(param2);
				}else {
					throw e;
				}
			}
		}
		return val;
	}
	
	

	private int keySize;
	/**秘钥位数**/
	public int keySize(){
		return keySize;
	}
	/**是否包含私钥**/
	public boolean hasPrivate(){
		return privateKey!=null;
	}
	
	
	/** 公钥 **/
	public RSAPublicKey publicKey;
	/** 私钥 **/
	public RSAPrivateKey privateKey;
	
	/**
	 * 用指定密钥大小创建一个新的RSA，会生成新密钥，出错抛异常
	 */
	public RSA_Util(int keySize) throws Exception {
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(keySize,new SecureRandom());
		KeyPair keyPair = keygen.generateKeyPair();
		publicKey=(RSAPublicKey)keyPair.getPublic();
		privateKey=(RSAPrivateKey)keyPair.getPrivate();
		this.keySize=keySize;
	}
	/**
	 * 通过指定的pem文件密钥或xml字符串密钥，创建一个RSA，pem或xml内可以只包含一个公钥或私钥，或都包含，出错抛异常
	 */
	public RSA_Util(String pemOrXML) throws Exception {
		RSA_PEM pem;
		if (pemOrXML.trim().startsWith("<")) {
			pem = RSA_PEM.FromXML(pemOrXML);
		} else {
			pem = RSA_PEM.FromPEM(pemOrXML);
		}
		publicKey=pem.getRSAPublicKey();
		privateKey=pem.getRSAPrivateKey();
		keySize=pem.keySize();
	}
	/**
	 * 通过一个pem对象创建RSA，pem为公钥或私钥，出错抛异常
	 */
	public RSA_Util(RSA_PEM pem) throws Exception {
		publicKey=pem.getRSAPublicKey();
		privateKey=pem.getRSAPrivateKey();
		keySize=pem.keySize();
	}
	
	
	
	
	
	
	
	/** 使用BouncyCastle的RSA实现进行加密，提供BouncyCastleProvider **/
	static private Provider BcProvider=null;
	/** 是否强制使用BouncyCastle的jar加密增强包进行RSA操作，为true时将不会使用Java的RSA实现 **/
	static public boolean IsUseBouncyCastle() {
		return BcProvider!=null;
	}
	/***
	 * 强制使用BouncyCastle的jar加密增强包进行RSA操作。只需在程序启动后调用一次即可，需先调用 Security.addProvider(new BouncyCastleProvider()) 进行全局注册，然后再调用本方法进行启用：UseBouncyCastle(BouncyCastleProvider.PROVIDER_NAME)，传入null取消启用
	 */
	static public void UseBouncyCastle(String providerName) {
		if(providerName==null || providerName.length()==0) {
			BcProvider=null;
			return;
		}
		Provider bc=Security.getProvider(providerName);
		if(bc==null) {
			throw new RuntimeException(T("需先调用一次Security.addProvider(new BouncyCastle"+"Provider())进行全局注册，然后才可以调用UseBouncyCastle","Need to call Security.addProvider(new BouncyCastle"+"Provider()) for global registration before calling UseBouncyCastle"));
		}
		BcProvider=bc;
	}
	
	
	
}
