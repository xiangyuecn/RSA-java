package com.github.xiangyuecn.rsajava;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;

/**
 * RSA_PEM测试控制台主程序
 * 
 * GitHub:https://github.com/xiangyuecn/RSA-java
 */
public class Test {
	
	public static void main(String[] args) throws Exception{
		//【请在这里编写你自己的测试代码】
		
		ShowMenu(args);
	}
	
	static void RSATest(boolean fast) throws Exception{
		//新生成一个RSA密钥，也可以通过已有的pem、xml文本密钥来创建RSA
		RSA_Util rsa = new RSA_Util(512);
		// RSA_Util rsa = new RSA_Util("pem或xml文本密钥");
		// RSA_Util rsa = new RSA_Util(RSA_PEM.FromPEM("pem文本密钥"));
		// RSA_Util rsa = new RSA_Util(RSA_PEM.FromXML("xml文本密钥"));
		
		//得到pem对象
		RSA_PEM pem=rsa.ToPEM(false);
		//提取密钥pem字符串
		String pem_pkcs1 = pem.ToPEM_PKCS1(false);
		String pem_pkcs8 = pem.ToPEM_PKCS8(false);
		//提取密钥xml字符串
		String xml = rsa.ToXML(false);
		
		AssertMsg(T("【"+rsa.keySize()+"私钥（XML）】：", "[ "+rsa.keySize()+" Private Key (XML) ]:"), rsa.keySize()==512);
		S(xml);
		S();
		ST("【"+rsa.keySize()+"私钥（PKCS#1）】：", "[ "+rsa.keySize()+" Private Key (PKCS#1) ]:");
		S(pem_pkcs1);
		S();
		ST("【"+rsa.keySize()+"公钥（PKCS#8）】：", "[ "+rsa.keySize()+" Public Key (PKCS#8) ]:");
		S(pem.ToPEM_PKCS8(true));
		S();
		
		
		String str = T("abc内容123", "abc123");
		String en=rsa.Encrypt("PKCS1", str);
		ST("【加密】：", "[ Encrypt ]:");
		S(en);
		
		ST("【解密】：", "[ Decrypt ]:");
		String de=rsa.Decrypt("PKCS1", en);
		AssertMsg(de, de.equals(str));
		
		if (!fast) {
			String str2 = str; for (int i = 0; i < 15; i++) str2 += str2;
			ST("【长文本加密解密】：", "[ Long text encryption and decryption ]:");
			AssertMsg(str2.length() + T("个字 OK"," characters OK"), rsa.Decrypt("PKCS1", rsa.Encrypt("PKCS1",str2)).equals(str2));
		}
		
		
		ST("【签名SHA1】：", "[ Signature SHA1 ]:");
		String sign = rsa.Sign("SHA1", str);
		S(sign);
		AssertMsg(T("校验 OK","Verify OK"), rsa.Verify("SHA1", sign, str));
		S();
		
		
		
		//用pem文本创建RSA
		RSA_Util rsa2=new RSA_Util(RSA_PEM.FromPEM(pem_pkcs8));
		RSA_PEM pem2=rsa2.ToPEM(false);
		ST("【用PEM新创建的RSA是否和上面的一致】：", "[ Is the newly created RSA with PEM consistent with the above ]:");
		Assert("XML：", pem2.ToXML(false) .equals( pem.ToXML(false) ));
		Assert("PKCS1：", pem2.ToPEM_PKCS1(false) .equals( pem.ToPEM_PKCS1(false) ));
		Assert("PKCS8：", pem2.ToPEM_PKCS8(false) .equals( pem.ToPEM_PKCS8(false) ));
		
		//用xml文本创建RSA
		RSA_Util rsa3=new RSA_Util(RSA_PEM.FromXML(xml));
		RSA_PEM pem3=rsa3.ToPEM(false);
		ST("【用XML新创建的RSA是否和上面的一致】：", "[ Is the newly created RSA with XML consistent with the above ]:");
		Assert("XML：", pem3.ToXML(false) .equals( pem.ToXML(false) ));
		Assert("PKCS1：", pem3.ToPEM_PKCS1(false) .equals( pem.ToPEM_PKCS1(false) ));
		Assert("PKCS8：", pem3.ToPEM_PKCS8(false) .equals( pem.ToPEM_PKCS8(false) ));
		
		
		//--------RSA_PEM私钥验证---------
		//使用PEM全量参数构造pem对象
		RSA_PEM pemX = new RSA_PEM(pem.Key_Modulus, pem.Key_Exponent, pem.Key_D
			, pem.Val_P, pem.Val_Q, pem.Val_DP, pem.Val_DQ, pem.Val_InverseQ);
		ST("【RSA_PEM是否和原始RSA一致】：", "[ Is RSA_PEM consistent with the original RSA ]:");
		S(pemX.keySize() + T("位"," bits"));
		Assert("XML：", pemX.ToXML(false) .equals( pem.ToXML(false) ));
		Assert("PKCS1：", pemX.ToPEM_PKCS1(false) .equals( pem.ToPEM_PKCS1(false) ));
		Assert("PKCS8：", pemX.ToPEM_PKCS8(false) .equals( pem.ToPEM_PKCS8(false) ));
		ST("仅公钥：", "Public Key Only:");
		Assert("XML：", pemX.ToXML(true) .equals( pem.ToXML(true) ));
		Assert("PKCS1：", pemX.ToPEM_PKCS1(true) .equals( pem.ToPEM_PKCS1(true) ));
		Assert("PKCS8：", pemX.ToPEM_PKCS8(true) .equals( pem.ToPEM_PKCS8(true) ));
		
		//--------RSA_PEM公钥验证---------
		RSA_PEM pemY = new RSA_PEM(pem.Key_Modulus, pem.Key_Exponent, null);
		ST("【RSA_PEM仅公钥是否和原始RSA一致】：", "[ RSA_PEM only public key is consistent with the original RSA ]:");
		S(pemY.keySize() + T("位"," bits"));
		Assert("XML：", pemY.ToXML(false) .equals( pem.ToXML(true) ));
		Assert("PKCS1：", pemY.ToPEM_PKCS1(false) .equals( pem.ToPEM_PKCS1(true) ));
		Assert("PKCS8：", pemY.ToPEM_PKCS8(false) .equals( pem.ToPEM_PKCS8(true) ));
		
		
		if (!fast) {
			//使用n、e、d构造pem对象
			RSA_PEM pem4 = new RSA_PEM(pem.Key_Modulus, pem.Key_Exponent, pem.Key_D);
			RSA_Util rsa4=new RSA_Util(pem4);
			ST("【用n、e、d构造解密】", "[ Construct decryption with n, e, d ]");
			de=rsa4.Decrypt("PKCS1",en);
			AssertMsg(de, de.equals(str));
			AssertMsg(T("校验 OK","Verify OK"), rsa4.Verify("SHA1", sign, str));
			
			
			//对调交换公钥私钥
			ST("【Unsafe|对调公钥私钥，私钥加密公钥解密】", "[ Unsafe | Swap the public key and private key, private key encryption and public key decryption ]");
			RSA_Util rsaPri=rsa.SwapKey_Exponent_D__Unsafe();
			RSA_Util rsaPub=new RSA_Util(rsa.ToPEM(true)).SwapKey_Exponent_D__Unsafe();
			String enPri=rsaPri.Encrypt("PKCS1", str);
			String signPub=rsaPub.Sign("SHA1", str);
			de=rsaPub.Decrypt("PKCS1",enPri);
			AssertMsg(de, de.equals(str));
			AssertMsg(T("校验 OK","Verify OK"), rsaPri.Verify("SHA1", signPub, str));
			
			rsa4 = rsaPri.SwapKey_Exponent_D__Unsafe();
			de=rsa4.Decrypt("PKCS1",en);
			AssertMsg(de, de.equals(str));
			AssertMsg(T("校验 OK","Verify OK"), rsa4.Verify("SHA1", sign, str));
		}
		
		
		if (!fast) {
			S();
			ST("【测试一遍所有的加密、解密填充方式】  按回车键继续测试...", "[ Test all the encryption and decryption padding mode ]   Press Enter to continue testing...");
			ReadIn();
			RSA_Util rsa5 = new RSA_Util(2048);
			testPaddings(false, rsa5, new RSA_Util(rsa5.ToPEM(true)), true);
		}
	}
	
	
	static void Assert(String msg, boolean check) throws Exception {
		AssertMsg(msg + check, check);
	}
	static void AssertMsg(String msg, boolean check) throws Exception {
		if (!check) throw new Exception(msg);
		System.out.println(msg);
	}
	
	
	
	/** 控制台输出一个换行 **/
	static private void S() {
		System.out.println();
	}
	/** 控制台输出内容 **/
	static private void S(String s) {
		System.out.println(s);
	}
	/** 控制台输出内容 + 简版多语言支持，根据当前语言返回中文或英文，简化调用{@link RSA_PEM#T(String, String)} **/
	static private void ST(String zh, String en) {
		System.out.println(T(zh, en));
	}
	/** 简版多语言支持，根据当前语言返回中文或英文，简化调用{@link RSA_PEM#T(String, String)} **/
	static private String T(String zh, String en) {
		return RSA_PEM.T(zh, en);
	}
	static public String ReadIn() throws Exception {
		ByteArrayOutputStream in=new ByteArrayOutputStream();
		while(true) {
			int byt=System.in.read();
			if(byt=='\r') continue;
			if(byt=='\n') {
				break;
			}
			if(in.size()>=2048) {//防止内存溢出，某些环境下可能会有无限的输入
				byte[] bytes=in.toByteArray();
				in=new ByteArrayOutputStream();
				in.write(bytes, bytes.length-1024, 1024);
			}
			in.write(byt);
		}
		return in.toString();
	}
	static String ReadPath(String tips, String tips2) throws Exception {
		while (true) {
			ST("请输入"+tips+"路径"+tips2+": ","Please enter "+tips+" path"+tips2+":");
			System.out.print("> ");
			String path = ReadIn().trim();
			if(path.length()==0 || path.startsWith("+")) {
				return path;
			}
			if(!new File(path).exists()) {
				ST("文件[" + path + "]不存在","File [" + path + "] does not exist");
				continue;
			}
			return path;
		}
	}
	static byte[] ReadFile(String path) throws Exception {
		ByteArrayOutputStream bs=new ByteArrayOutputStream();
		byte[] buffer=new byte[32*1024]; int len;
		try(FileInputStream in=new FileInputStream(path)){
			while((len=in.read(buffer))!=-1) {
				bs.write(buffer, 0, len);
			}
		}
		return bs.toByteArray();
	}
	static void WriteFile(String path, byte[] val) throws Exception {
		try(FileOutputStream out=new FileOutputStream(path)){
			out.write(val);
		}
	}
	static String HR="-----------------------------------";

	
	
	
	static boolean CanLoad_BouncyCastle() {
		try {
			Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
			return true;
		}catch(Exception e) {
			return false;
		}
	}
	static void printEnv() {
		S("Java Version: "+System.getProperty("java.version")+" | "+System.getProperty("os.name")+"   RSA_PEM.Lang="+RSA_PEM.Lang());
		String errs="";
		try {
			Signature.getInstance("RSASSA-PSS");
		}catch(Exception e) {
			errs+=errs.length()>0?T("、",", "):"";
			errs+=T("PSS签名填充模式（其他填充模式不影响）","PSS signature padding mode (other padding modes do not affect)");
		}
		try {
			MessageDigest.getInstance("SHA-512/256");
		}catch(Exception e) {
			errs+=errs.length()>0?T("、",", "):"";
			errs+=T("SHA-512/224（/256）摘要算法","SHA-512/224 (/256) digest algorithm");
		}
		try {
			MessageDigest.getInstance("SHA3-256");
		}catch(Exception e) {
			errs+=errs.length()>0?T("、",", "):"";
			errs+=T("SHA3系列摘要算法","SHA3 series digest algorithm");
		}
		if(errs.length()>0) {
			ST("*** 当前Java版本太低，不支持："+errs+"；如需获得这些功能支持，解决办法1：升级使用高版本Java来运行本测试程序；解决办法2：引入BouncyCastle的jar加密增强包来兼容低版本Java，先到 https://www.bouncycastle.org/latest_releases.html 下载 bcprov-jdk**-**.jar 放到本测试程序源码目录，然后通过测试菜单B进行注册即可得到全部支持。","*** The current Java version is too low to support: "+errs+"; if you want to obtain these functions, solution 1: upgrade and use a higher version of Java to run this test program; solution 2: introduce the jar encryption enhancement package of BouncyCastle to be compatible with lower Version Java, first go to https://www.bouncycastle.org/latest_releases.html to download bcprov-jdk**-**.jar and put it in the source code directory of this test program, and then register through test menu B to get full support.");
		}
	}
	static Provider BcProvider=null;
	static void testProvider(boolean checkOpenSSL) throws Exception{
		if(CanLoad_BouncyCastle()) {
			if(BcProvider==null) {
				ST("检测到BouncyCastle加密增强包，是否要进行注册？(Y/N) Y","The BouncyCastle encryption enhancement package is detected, do you want to register? (Y/N) Y");
			}else {
				ST("已注册BouncyCastle加密增强包，是否要保持注册？(Y/N) Y","BouncyCastle encryption enhancement package has been registered, do you want to keep it registered? (Y/N) Y");
			}
			System.out.print("> ");
			String val = ReadIn().trim().toUpperCase();
			try {
				if(BcProvider==null && !"N".equals(val)) {
					Class<?> cls=Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
					Provider bc=(Provider)cls.getConstructor().newInstance();
					Security.addProvider(bc);
					RSA_Util.UseBouncyCastle(bc.getName());
					BcProvider=bc;
					ST("已注册BouncyCastle加密增强包","BouncyCastle encryption enhancement package registered");
				}
				if(BcProvider!=null && "N".equals(val)) {
					Security.removeProvider(BcProvider.getName());
					RSA_Util.UseBouncyCastle(null);
					BcProvider=null;
					ST("已取消注册BouncyCastle加密增强包","Unregistered BouncyCastle encryption enhancement package");
				}
			}catch(Exception e) {
				S(T("BouncyCastle操作失败：","BouncyCastle operation failed: ")+e.getMessage());
			}
		}
		printEnv();
		S();
		
		S("Security.getProviders:");
		Provider[] ps=Security.getProviders();
		for(Provider s : ps) {
			S("    Provider: "+s.toString());
		}
		S();
		
		String[] Hashs=new String[] {
				"SHA-1","SHA-256","SHA-224","SHA-384","SHA-512"
				,"SHA3-256","SHA3-224","SHA3-384","SHA3-512"
				,"SHA-512/224","SHA-512/256","MD5"
			};
		
		S("MessageDigest.getInstance"+T("支持情况："," support status:"));
		{
			ArrayList<String> S=new ArrayList<String>(Arrays.asList(Hashs));
			S.add("MD2");
			S.add("SHAKE128"); S.add("SHAKE256");//https://blog.csdn.net/weixin_42579622/article/details/111644921
			for(String s : S) {
				String key=s;
				try {
					MessageDigest v=MessageDigest.getInstance(key);
					S("      "+key+" | Provider: "+v.getProvider().toString());
				}catch(Exception e) {
					S("  [x] "+key);
				}
			}
		}

		S("Cipher.getInstance"+T("支持情况："," support status:"));
		for(int i=0;i<1;i++) {
			String v1=i==9999?"NONE":"ECB";
			ArrayList<String> S=new ArrayList<>(Arrays.asList(new String[] {"NoPadding"
					,"PKCS1Padding"
					,"OAEPPadding"}));
			for(String s : Hashs) {
				S.add("OAEPwith"+s+"andMGF1Padding");
			}
			for(String s : S) {
				String key="RSA/"+v1+"/"+s,key2=key;
				while(true) {
					try {
						Cipher v=Cipher.getInstance(key2);
						S("      "+key+" | Provider: "+v.getProvider().toString());
					}catch(Exception e) {
						if(key2.contains("512/2")) {
							key2=key2.replace("/224", "(224)").replace("/256", "(256)");
							continue;
						}
						S("  [x] "+key);
					}
					break;
				}
			}
		}
		
		S("Signature.getInstance"+T("支持情况："," support status:"));
		for(int i=0;i<3;i++) {
			String v2=i==1?"/PSS":"";
			String[] S=i==2?new String[] {"RSASSA-PSS"}:Hashs;
			for(String s : S) {
				String key=i==2?s:(s.replace("SHA-", "SHA")+"withRSA"+v2),key2=key;
				while(true) {
					try {
						Signature v=Signature.getInstance(key2);
						S("      "+key+" | Provider: "+v.getProvider().toString());
					}catch(Exception e) {
						if(key2.contains("512/2")) {
							key2=key2.replace("/224", "(224)").replace("/256", "(256)");
							continue;
						}
						S("  [x] "+key);
					}
					break;
				}
			}
		}
		
		S(HR);
		ST("测试一遍所有的加密、解密填充方式：","Test all the encryption and decryption padding mode:");
		RSA_Util rsa = new RSA_Util(2048);
		testPaddings(checkOpenSSL, rsa, new RSA_Util(rsa.ToPEM(true)), true);

		S(HR);
		ST("Unsafe|是否要对调公钥私钥（私钥加密公钥解密）重新测试一遍？(Y/N) N", "Unsafe | Do you want to swap the public and private keys (private key encryption and public key decryption) and test again? (Y/N) N");
		System.out.print("> ");
		String yn = ReadIn().trim().toUpperCase();
		if (yn.equals("Y")) {
			RSA_Util rsaPri = rsa.SwapKey_Exponent_D__Unsafe();
			RSA_Util rsaPub = new RSA_Util(rsa.ToPEM(true)).SwapKey_Exponent_D__Unsafe();
			testPaddings(checkOpenSSL, rsaPub, rsaPri, true);
		}
	}
	/** 测试一遍所有的加密、解密填充方式 **/
	static int testPaddings(boolean checkOpenSSL, RSA_Util rsaPri, RSA_Util rsaPub, boolean log) {
		int errCount=0;
		ArrayList<String> errMsgs=new ArrayList<>();
		String txt="1234567890";
		if(!checkOpenSSL) {
			txt+=txt+txt+txt+txt; txt+=txt;//100
			txt+=txt+txt+txt+txt; txt+=txt+"a";//1001
		}
		byte[] txtData=txt.getBytes(Charset.forName("utf-8"));
		
		if(checkOpenSSL) {
			try {
				runOpenSSL(rsaPri.hasPrivate()?rsaPri:rsaPub, txtData);
			}catch(Exception e) {
				S(T("运行OpenSSL失败：","Failed to run OpenSSL: ")+e.getMessage());
				return errCount;
			}
		}
		
		String[] encKeys=RSA_Util.RSAPadding_Enc_DefaultKeys();
		for(String type : encKeys) {
			String errMsg="";
			try {
				{
					byte[] enc=rsaPub.Encrypt(type, txtData);
					byte[] dec=rsaPri.Decrypt(type, enc);
					boolean isOk=true;
					if(dec.length!=txtData.length) {
						isOk=false;
					}else {
						for(int i=0;i<dec.length;i++) {
							if(dec[i]!=txtData[i]) {
								isOk=false;break;
							}
						}
					}
					if(!isOk) {
						errMsg=T("解密结果不一致","Decryption results are inconsistent");
						throw new Exception(errMsg);
					}
				}
				if(checkOpenSSL) {
					byte[] enc;
					try {
						enc=testOpenSSL(true, type);
					}catch(Exception e) {
						errMsg="+OpenSSL: "+T("OpenSSL加密出错", "OpenSSL encryption error");
						throw e;
					}
					byte[] dec=rsaPri.Decrypt(type, enc);
					boolean isOk=true;
					if(dec.length!=txtData.length) {
						isOk=false;
					}else {
						for(int i=0;i<dec.length;i++) {
							if(dec[i]!=txtData[i]) {
								isOk=false;break;
							}
						}
					}
					if(!isOk) {
						errMsg="+OpenSSL: "+T("解密结果不一致","Decryption results are inconsistent");
						throw new Exception(errMsg);
					}
				}
				if(log) {
					S("     "+(checkOpenSSL?" [+OpenSSL]":"")+" "+T("加密解密：","Encryption decryption: ")+type+" | "+RSA_Util.RSAPadding_Enc(type));
				}
			}catch (Exception e) {
				if(!log && RSA_Util.IsJavaLowVerSupportError(e)) {
					//NOOP
				}else {
					errCount++;
					if(errMsg.length()==0)errMsg=T("加密解密出现异常","An exception occurred in encryption decryption");
					errMsg="  [x] "+errMsg+": "+type+" | "+RSA_Util.RSAPadding_Enc(type);
					S(errMsg);
					errMsgs.add(errMsg+T("。",". ")+e.getMessage());
				}
			}
		}
		
		String[] signKeys=RSA_Util.RSAPadding_Sign_DefaultKeys();
		for(String type : signKeys) {
			String errMsg="";
			try {
				{
					byte[] sign=rsaPri.Sign(type, txtData);
					boolean isOk=rsaPub.Verify(type, sign, txtData);
					if(!isOk) {
						errMsg=T("未通过校验","Failed verification");
						throw new Exception(errMsg);
					}
				}
				if(checkOpenSSL) {
					byte[] sign;
					try {
						sign=testOpenSSL(false, type);
					}catch(Exception e) {
						errMsg="+OpenSSL: "+T("OpenSSL签名出错", "OpenSSL signature error");
						throw e;
					}
					boolean isOk=rsaPub.Verify(type, sign, txtData);
					if(!isOk) {
						errMsg="+OpenSSL: "+T("未通过校验","Failed verification");
						throw new Exception(errMsg);
					}
				}
				if(log) {
					S("     "+(checkOpenSSL?" [+OpenSSL]":"")+" "+T("签名验证：","Signature verification: ")+type+" | "+RSA_Util.RSAPadding_Sign(type));
				}
			}catch (Exception e) {
				if(!log && RSA_Util.IsJavaLowVerSupportError(e)) {
					//NOOP
				}else if(!log && type.equals("PSS+MD5")) {
					//NOOP 不同实现下不一定支持，没有提前检测
				}else {
					errCount++;
					if(errMsg.length()==0) errMsg=T("签名验证出现异常","An exception occurred in signature verification");
					errMsg="  [x] "+errMsg+": "+type+" | "+RSA_Util.RSAPadding_Sign(type);
					S(errMsg);
					errMsgs.add(errMsg+T("。",". ")+e.getMessage());
				}
			}
		}
		if(log) {
			if(errMsgs.size()==0) {
				ST("填充方式全部测试通过。", "All padding mode tests passed.");
			}else {
				ST("按回车键显示详细错误消息...", "Press Enter to display detailed error message...");
				try{ ReadIn(); }catch(Exception e) {}
			}
		}
		if(errMsgs.size()>0) {
			S(String.join("\n", errMsgs));
		}
		closeOpenSSL();
		return errCount;
	}
	/** 多线程并发调用同一个RSA **/
	static void threadRun() throws Exception {
		int ThreadCount=Math.max(5, Runtime.getRuntime().availableProcessors()-1);
		AtomicBoolean Abort=new AtomicBoolean(false);
		AtomicInteger Count=new AtomicInteger(0);
		AtomicInteger ErrCount=new AtomicInteger(0);
		RSA_Util rsa=new RSA_Util(2048);
		RSA_Util rsaPub=new RSA_Util(rsa.ToPEM(true));
		S(T("正在测试中，线程数：","Under test, number of threads: ")+ThreadCount+T("，按回车键结束测试...",", press enter to end the test..."));
		
		for(int i=0;i<ThreadCount;i++) {
			new Thread(new Runnable() {
				public void run() {
					while(!Abort.get()) {
						int err=testPaddings(false, rsa, rsaPub, false);
						if(err>0) {
							ErrCount.addAndGet(err);
						}
						Count.incrementAndGet();
					}
				}
			}).start();
		}
		
		long t1=System.currentTimeMillis();
		new Thread(new Runnable() {
			public void run() {
				while(!Abort.get()) {
					System.out.print("\r"+T("已测试"+Count.get()+"次，","Tested "+Count.get()+" times, ")
							+ErrCount.get()+T("个错误，"," errors, ")
							+T("耗时","")+(System.currentTimeMillis()-t1)/1000+T("秒"," seconds total"));
					try {
						Thread.sleep(1000);
					}catch (Exception e) {}
				}
			}
		}).start();
		
		ReadIn();
		Abort.set(true);
		ST("多线程并发调用同一个RSA测试已结束。","Multiple threads concurrently calling the same RSA test is over.");
		S();
	}
	
	
	
	static void keyTools() throws Exception {
		ST("===== RSA密钥工具：生成密钥、转换密钥格式 ====="
		 , "===== RSA key tool: generate key, convert key format =====");
		ST("请使用下面可用命令进行操作，命令[]内的为可选参数，参数可用\"\"包裹。","Please use the following commands to operate. The parameters in the command `[]` are optional parameters, and the parameters can be wrapped with \"\".");
		S(HR);
		S("`new 1024 [-pkcs8] [saveFile [puboutFile]]`: "+T("生成新的RSA密钥，指定位数和格式：xml、pkcs1、或pkcs8（默认），提供saveFile可保存私钥到文件，提供puboutFile可额外保存一个公钥文件","Generate a new RSA key, specify the number of digits and format: xml, pkcs1, or pkcs8 (default), provide saveFile to save the private key to a file, and provide puboutFile to save an additional public key file"));
		S(HR);
		S("`convert -pkcs1 [-pubout] [-swap] oldFile [newFile]`: "+T("转换密钥格式，提供已有密钥文件oldFile（支持xml、pem格式公钥或私钥），指定要转换成的格式：xml、pkcs1、或pkcs8，提供了-pubout时只导出公钥，提供了-swap时交换公钥指数私钥指数（非常规的：私钥加密公钥解密），提供newFile可保存到文件","To convert the key format, provide the existing key file oldFile (support xml, pem format public key or private key), specify the format to be converted into: xml, pkcs1, or pkcs8, only export the public key when -pubout is provided, swap public key exponent and private key exponent when -swap is provided (unconventional: private key encryption and public key decryption), and provide newFile Can save to file"));
		S(HR);
		S("`exit`: "+T("输入 exit 退出工具","Enter exit to quit the tool"));
		loop: while(true){
			System.out.print("> ");
			String inStr=ReadIn().trim();
			if(inStr.length()==0) {
				ST("输入为空，请重新输入！如需退出请输入exit","The input is empty, please re-enter! If you need to exit, please enter exit");
				continue;
			}
			if(inStr.toLowerCase().equals("exit")) {
				ST("bye! 已退出。","bye! has exited.");
				S();
				return;
			}
			ArrayList<String> args=new ArrayList<>();
			Pattern exp=Pattern.compile("(-?)(?:([^\"\\s]+)|\"(.*?)\")\\s*");
			Matcher m=exp.matcher(inStr);
			StringBuffer sb = new StringBuffer();
			while(m.find()) {
				if(m.group(2)!=null&&m.group(2).length()>0) {
					args.add(m.group(1)+m.group(2));
				}else {
					args.add(m.group(1)+m.group(3));
				}
				m.appendReplacement(sb, "");
			}
			m.appendTail(sb);
			if(sb.length()>0) {
				ST("参数无效："+sb,"Invalid parameter: "+sb);
				continue;
			}
			
			String cmdName=args.get(0).toLowerCase(); args.remove(0);
			boolean nextSave=false;
			RSA_Util rsa=null; String type="", save="", save2=""; boolean pubOut=false;
			
			if(cmdName.equals("new")) {// 生成新的pem密钥
				type="pkcs8"; String len="";
				while(args.size()>0) {
					String param=args.get(0),p=param.toLowerCase(); args.remove(0);
					
					m=Pattern.compile("^(\\d+)$").matcher(p);
					if(m.find()) { len=m.group(1); continue; }
					
					m=Pattern.compile("^-(xml|pkcs1|pkcs8)$").matcher(p);
					if(m.find()) { type=m.group(1); continue; }
					
					if(save.length()==0 && !p.startsWith("-")) { save=param; continue; }
					if(save2.length()==0 && !p.startsWith("-")) { save2=param; continue; }
					
					ST("未知参数："+param,"Unknown parameter: "+param);
					continue loop;
				}
				if(len.length()==0) { ST("请提供密钥位数！","Please provide key digits!");continue loop; }
				try {
					rsa=new RSA_Util(Integer.parseInt(len));
				}catch(Exception e) {
					S(T("生成密钥出错：","Error generating key: ")+e.getMessage());
					continue loop;
				}
				nextSave=true;
			}
			
			if(cmdName.equals("convert")) {// 转换密钥格式
				String old=""; boolean swap=false;
				while(args.size()>0) {
					String param=args.get(0),p=param.toLowerCase(); args.remove(0);
					
					m=Pattern.compile("^-(xml|pkcs1|pkcs8)$").matcher(p);
					if(m.find()) { type=m.group(1); continue; }
					
					if(p.equals("-pubout")) { pubOut=true; continue; }
					if(p.equals("-swap")) { swap=true; continue; }
					
					if(old.length()==0 && !p.startsWith("-")) { old=param; continue; }
					
					if(save.length()==0 && !p.startsWith("-")) { save=param; continue; }
					
					ST("未知参数："+param,"Unknown parameter: "+param);
					continue loop;
				}
				if(type.length()==0) { ST("请提供要转换成的格式！","Please provide the format to convert to!");continue loop; }
				if(old.length()==0) { ST("请提供已有密钥文件！","Please provide an existing key file!");continue loop; }
				try {
					String oldTxt=new String(ReadFile(old),"utf-8");
					rsa=new RSA_Util(oldTxt);
					if(swap) rsa=rsa.SwapKey_Exponent_D__Unsafe();
				}catch(Exception e) {
					S(T("读取密钥文件出错","Error reading key file ")+" ("+old+"): "+e.getMessage());
					continue loop;
				}
				nextSave=true;
			}
			
			while(nextSave) {
				String val;
				if(type.equals("xml")) {
					val=rsa.ToXML(pubOut);
				}else {
					boolean pkcs8=type.equals("pkcs8");
					val=rsa.ToPEM(false).ToPEM(pubOut, pkcs8, pkcs8);
				}
				if(save.length()==0) {
					S(val);
				}else {
					save=new File(save).getAbsolutePath();
					try{
						WriteFile(save, val.getBytes("utf-8"));
					}catch(Exception e) {
						S(T("保存文件出错","Error saving file ")+" ("+save+"): "+e.getMessage());
					}
					S(T("密钥文件已保存到：","The key file has been saved to: ")+save);
				}
				if(save2.length()>0) {
					save=save2; save2="";
					pubOut=true;
					continue;
				}
				S();
				continue loop;
			}
			ST("未知命令："+cmdName,"Unknown command: "+cmdName);
		}
	}
	
	
	
	static RSA_PEM loadKey=null; static String loadKeyFile="";
	/** 设置：加载密钥PEM文件 **/
	static void setLoadKey() throws Exception {
		String path=ReadPath(T("密钥文件","Key File")
				, T("，或文件夹（内含private.pem、test.txt）。或输入'+1024 pkcs8'生成一个新密钥（填写位数、pkcs1、pkcs8）", ", or a folder (containing private.pem, test.txt). Or enter '+1024 pkcs8' to generate a new key (fill in digits, pkcs1, pkcs8) "));
		if(path.startsWith("+")) {//创建一个新密钥
			Matcher m=Pattern.compile("^\\+(\\d+)\\s+pkcs([18])$",Pattern.CASE_INSENSITIVE).matcher(path);
			if(!m.find()) {
				ST("格式不正确，请重新输入！","The format is incorrect, please re-enter!");
				setLoadKey();
			}else {
				int keySize=Integer.parseInt(m.group(1));
				RSA_Util rsa=new RSA_Util(keySize);
				boolean isPkcs8=m.group(2).equals("8");
				RSA_PEM pem=rsa.ToPEM(false);
				S(keySize+T("位私钥已生成，请复制此文本保存到private.pem文件："," bit private key has been generated. Please copy this text and save it to the private.pem file:"));
				S(pem.ToPEM(false, isPkcs8, isPkcs8));
				S(keySize+T("位公钥已生成，请复制此文本保存到public.pem文件："," bit public key has been generated. Please copy this text and save it to the public.pem file:"));
				S(pem.ToPEM(true, isPkcs8, isPkcs8));
				waitAnyKey=true;
			}
			return;
		}
		if(path.length()==0 && loadKeyFile.length()==0) {
			ST("未输入文件，已取消操作","No file input, operation cancelled");
			return;
		}
		if(path.length()==0) {
			path=loadKeyFile;
			ST("重新加载密钥文件","Reload key file");
		}
		
		if(new File(path).isDirectory()) {
			String txtPath=path+File.separator+"test.txt";
			path=path+File.separator+"private.pem";
			if(!new File(path).exists()) {
				ST("此文件夹中没有private.pem文件！","There is no private.pem file in this folder!");
				setLoadKey();
				return;
			}
			if(new File(txtPath).exists()) {//顺带加载文件夹里面的目标源文件
				loadSrcBytes=ReadFile(txtPath);
				loadSrcFile=txtPath;
			}
		}
		String pem=new String(ReadFile(path),"utf-8");
		loadKey=RSA_PEM.FromPEM(pem);
		loadKeyFile=path;
	}
	
	static byte[] loadSrcBytes=null; static String loadSrcFile="";
	/** 设置：加载目标源文件 **/
	static void setLoadSrcBytes() throws Exception {
		String path=ReadPath(T("目标源文件","Target Source File"), "");
		if(path.length()==0 && loadSrcFile.length()==0) {
			ST("未输入文件，已取消操作","No file input, operation cancelled");
			return;
		}
		if(path.length()==0) {
			path=loadSrcFile;
			ST("重新加载目标源文件","Reload target source file");
		}
		loadSrcBytes=ReadFile(path);
		loadSrcFile=path;
	}
	
	static String encType="";
	/** 设置加密填充模式 **/
	static boolean setEncType() throws Exception {
		S(T("请输入加密填充模式","Please enter the encryption Padding mode")
			+(encType.length()>0?T("，回车使用当前值",", press Enter to use the current value ")+encType:"")
			+T("；填充模式取值可选：","; Padding mode values: ")+String.join(", ", RSA_Util.RSAPadding_Enc_DefaultKeys())
			+T(", 或其他支持的值",", or other supported values"));
		System.out.print("> ");
		String val = ReadIn().trim();
		if(val.length()>0) {
			encType=val;
		}
		if(encType.length()==0) {
			ST("未设置，已取消操作","Not set, operation canceled");
		}
		return encType.length()>0;
	}
	/** 加密 **/
	static void execEnc() throws Exception {
		String save=loadSrcFile+".enc.bin";
		S(T("密钥文件：","Key file: ")+loadKeyFile);
		S(T("目标文件：","Target file: ")+loadSrcFile);
		S(T("填充模式：","Padding mode: ")+encType+" | "+RSA_Util.RSAPadding_Enc(encType));
		ST("正在加密目标源文件...","Encrypting target source file...");
		RSA_Util rsa=new RSA_Util(loadKey);
		long t1=System.currentTimeMillis();
		byte[] data=rsa.Encrypt(encType, loadSrcBytes);
		S(T("加密耗时：","Encryption time: ")+(System.currentTimeMillis()-t1)+"ms");
		WriteFile(save, data);
		S(T("已加密，结果已保存：","Encrypted, the result is saved: ")+save);
	}
	/** 解密对比 **/
	static void execDec() throws Exception {
		String encPath=loadSrcFile+".enc.bin";
		S(T("密钥文件：","Key file: ")+loadKeyFile);
		S(T("密文文件：","Ciphertext file: ")+encPath);
		S(T("对比文件：","Compare files: ")+loadSrcFile);
		S(T("填充模式：","Padding mode: ")+encType+" | "+RSA_Util.RSAPadding_Enc(encType));
		byte[] data=ReadFile(encPath);
		ST("正在解密文件...","Decrypting file...");
		RSA_Util rsa=new RSA_Util(loadKey);
		long t1=System.currentTimeMillis();
		byte[] val=rsa.Decrypt(encType, data);
		S(T("解密耗时：","Decryption time: ")+(System.currentTimeMillis()-t1)+"ms");
		WriteFile(loadSrcFile+".dec.txt",val);
		boolean isOk=true;
		if(val.length!=loadSrcBytes.length) {
			isOk=false;
		}else {
			for(int i=0;i<val.length;i++) {
				if(val[i]!=loadSrcBytes[i]) {
					isOk=false;break;
				}
			}
		}
		if(isOk) {
			ST("解密成功，和对比文件的内容一致。","The decryption is successful, which is consistent with the content of the comparison file.");
			return;
		}
		throw new Exception(T("解密结果和对比文件的内容不一致！","The decryption result is inconsistent with the content of the comparison file!"));
	}
	
	
	static String signType="";
	/** 设置签名hash+填充模式 **/
	static boolean setSignType() throws Exception {
		S(T("请输入签名Hash+填充模式","Please enter the signature Hash+Padding mode")
			+(signType.length()>0?T("，回车使用当前值",", press Enter to use the current value ")+signType:"")
			+T("；签名模式取值可选：","; Signature mode values: ")+String.join(", ", RSA_Util.RSAPadding_Sign_DefaultKeys())
			+T(", 或其他支持的值",", or other supported values"));
		System.out.print("> ");
		String val = ReadIn().trim();
		if(val.length()>0) {
			signType=val;
		}
		if(signType.length()==0) {
			ST("未设置，已取消操作","Not set, operation canceled");
		}
		return signType.length()>0;
	}
	/** 签名 **/
	static void execSign() throws Exception {
		String save=loadSrcFile+".sign.bin";
		S(T("密钥文件：","Key file: ")+loadKeyFile);
		S(T("目标文件：","Target file: ")+loadSrcFile);
		S(T("签名模式：","Signature mode: ")+signType+" | "+RSA_Util.RSAPadding_Sign(signType));
		ST("正在给目标源文件签名...","Signing target source file...");
		RSA_Util rsa=new RSA_Util(loadKey);
		byte[] data=rsa.Sign(signType, loadSrcBytes);
		WriteFile(save, data);
		S(T("已签名，结果已保存：","Signed, results saved: ")+save);
	}
	/** 验证签名 **/
	static void execVerify() throws Exception {
		String binPath=loadSrcFile+".sign.bin";
		S(T("密钥文件：","Key file: ")+loadKeyFile);
		S(T("目标文件：","Target file: ")+loadSrcFile);
		S(T("签名文件：","Signature file: ")+binPath);
		S(T("签名模式：","Signature mode: ")+signType+" | "+RSA_Util.RSAPadding_Sign(signType));
		byte[] data=ReadFile(binPath);
		ST("正在验证签名...","Verifying signature...");
		RSA_Util rsa=new RSA_Util(loadKey);
		boolean val=rsa.Verify(signType, data, loadSrcBytes);
		if(val) {
			ST("签名验证成功。","Signature verification successful.");
			return;
		}
		throw new Exception(T("签名验证失败！","Signature verification failed!"));
	}
	
	
	
	
	
	/** 调用openssl相关测试代码 **/
	static void runOpenSSL(RSA_Util rsa, byte[] data) throws Exception{
		String shell="/bin/bash", charset="utf-8";
		if(System.getProperty("os.name").toLowerCase().contains("windows")) {
			shell="cmd"; charset="gbk";
		}
		
		S(T("正在打开OpenSSL...","Opening OpenSSL...")+"    Shell: "+shell);
		closeOpenSSL();
		openSSLProc=Runtime.getRuntime().exec(new String[] { shell });
		openSSLWrite=new BufferedWriter(new OutputStreamWriter(openSSLProc.getOutputStream(), charset));
		openSSLRead=new BufferedReader(new InputStreamReader(openSSLProc.getInputStream(), charset));
		openSSLErrRead=new BufferedReader(new InputStreamReader(openSSLProc.getErrorStream(), charset));
		openSSLBuffer=new StringBuffer();
		openSSLErrBuffer=new StringBuffer();
		openSSLThread1=new Thread(new Runnable() {
			public void run() {
				try {
					while(true){
						String line=openSSLRead.readLine();
						if(line!=null) {
							openSSLBuffer.append(line).append('\n');
						}
					}
				}catch (Exception e) { }
			}
		});
		openSSLThread2=new Thread(new Runnable() {
			public void run() {
				try {
					while(true){
						String line=openSSLErrRead.readLine();
						if(line!=null) {
							openSSLErrBuffer.append(line).append('\n');
						}
					}
				}catch (Exception e) { }
			}
		});
		openSSLThread1.start();
		openSSLThread2.start();
		
		WriteFile("test_openssl_key.pem", rsa.ToPEM(false).ToPEM_PKCS8(false).getBytes("utf-8"));
		WriteFile("test_openssl_data.txt", data);
		
		byte[] no=new byte[rsa.keySize()/8];
		System.arraycopy(data, 0, no, no.length-data.length, data.length);
		WriteFile("test_openssl_data.txt.nopadding.txt", no);
		
		openSSLWrite.write("openssl version\necho "+openSSLBoundary+"\n");
		openSSLWrite.flush();
		while(true) {
			if(openSSLBuffer.indexOf(openSSLBoundary)!=-1) {
				if(openSSLErrBuffer.length()>0) {
					closeOpenSSL();
					throw new Exception(T("打开OpenSSL出错：","Error opening OpenSSL: ")+openSSLErrBuffer.toString().trim());
				}
				S("OpenSSL Version: "+openSSLBuffer.toString().trim());
				break;
			}
			Thread.sleep(10);
		}
	}
	static private Process openSSLProc;
	static private BufferedWriter openSSLWrite;
	static private BufferedReader openSSLRead, openSSLErrRead;
	static private StringBuffer openSSLBuffer, openSSLErrBuffer;
	static private Thread openSSLThread1, openSSLThread2;
	static private final String openSSLBoundary="--openSSL boundary--";
	static void closeOpenSSL() {
		if(openSSLProc==null)return;
		try {openSSLWrite.close();}catch(Exception e) { }
		try {openSSLRead.close();}catch(Exception e) { }
		try {openSSLErrRead.close();}catch(Exception e) { }
		try {openSSLProc.destroy();}catch(Exception e) { }
		try {openSSLThread1.interrupt(); openSSLThread2.interrupt();}catch(Exception e) { }
		openSSLProc=null;
	}
	static byte[] testOpenSSL(boolean encOrSign, String mode) throws Exception {
		boolean debug=false; String cmd="";
		String keyFile="test_openssl_key.pem",txtFile="test_openssl_data.txt";
		String save=txtFile+(encOrSign?".enc.bin":".sign.bin");
		if(encOrSign) {//加密
			if(mode.equals("NO")) {
				cmd="openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:none -in "+txtFile+".nopadding.txt -inkey "+keyFile+" -out "+save;
			} else if(mode.equals("PKCS1")) {
				cmd="openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:pkcs1 -in "+txtFile+" -inkey "+keyFile+" -out "+save;
			} else if(mode.startsWith("OAEP+")) {
				String hash=mode.replace("OAEP+", "").replace("-512/", "512-");
				cmd="openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:"+hash+" -in "+txtFile+" -inkey "+keyFile+" -out "+save;
			}
		}else {//签名
			if(mode.startsWith("PKCS1+")) {
				String hash=mode.replace("PKCS1+", "").replace("-512/", "512-");
				cmd="openssl dgst -"+hash+" -binary -sign "+keyFile+" -out "+save+" "+txtFile;
			}else if(mode.startsWith("PSS+")) {
				String hash=mode.replace("PSS+", "").replace("-512/", "512-");
				cmd="openssl dgst -"+hash+" -binary -out "+txtFile+".hash "+txtFile;
				cmd+="\n";
				cmd+="openssl pkeyutl -sign -pkeyopt digest:"+hash+" -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -in "+txtFile+".hash -inkey "+keyFile+" -out "+save;
			}
		}
		if(cmd.length()==0) {
			String msg=T("无效mode：","Invalid mode: ")+mode;
			S("[OpenSSL Code Error] "+msg);
			throw new Exception(msg);
		}
		if(new File(save).exists()) {
			new File(save).delete();
		}

		if(debug) S("[OpenSSL Cmd]["+mode+"]"+cmd);
		openSSLBuffer.setLength(0);
		openSSLErrBuffer.setLength(0);
		openSSLWrite.write(cmd+"\n");
		openSSLWrite.write("echo "+openSSLBoundary+"\n");
		openSSLWrite.flush();
		
		while (true) {
			if(openSSLBuffer.indexOf(openSSLBoundary)!=-1) {
				if(openSSLErrBuffer.length()>0) {
					if(debug) S("[OpenSSL Error]\n"+openSSLErrBuffer+"\n[End]");
					throw new Exception("OpenSSL Error: "+openSSLErrBuffer.toString().trim());
				}
				if(debug) S("[OpenSSL Output]\n"+openSSLBuffer+"\n[End] save:"+new File(save).getAbsolutePath());
				break;
			}
			Thread.sleep(10);
		}
		return ReadFile(save);
	}
	
	static void showOpenSSLTips() {
		ST("===== OpenSSL中RSA相关的命令行调用命令 ====="
		 , "===== RSA-related command-line invocation commands in OpenSSL =====");
		S();
		ST("::先准备一个测试文件 test.txt 里面填少量内容，openssl不支持自动分段加密"
		 , "::First prepare a test file test.txt and fill in a small amount of content, openssl does not support automatic segmentation encryption");
		S();
		ST("::生成新密钥", "::Generate new key");
		S("openssl genrsa -out private.pem 1024");
		S();
		ST("::提取公钥PKCS#8","::Extract public key PKCS#8");
		S("openssl rsa -in private.pem -pubout -out public.pem");
		S();
		ST("::转换成RSAPublicKey PKCS#1", "::Convert to RSAPublicKey PKCS#1");
		S("openssl rsa -pubin -in public.pem -RSAPublicKey_out -out public.pem.rsakey");
		ST("::测试RSAPublicKey PKCS#1，不出意外会出错。因为这个公钥里面没有OID，通过RSA_PEM转换成PKCS#8自动带上OID就能正常加密"
		 , "::Test RSAPublicKey PKCS#1, no accident will go wrong. Because there is no OID in this public key, it can be encrypted normally by converting RSA_PEM into PKCS#8 and automatically bringing OID");
		S("echo abcd123 | openssl rsautl -encrypt -inkey public.pem.rsakey -pubin");
		S();
		S();
		S();
		ST("::加密和解密，填充方式：PKCS1"
		 , "::Encryption and decryption, padding mode: PKCS1");
		S("openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:pkcs1 -in test.txt -pubin -inkey public.pem -out test.txt.enc.bin");
		S("openssl pkeyutl -decrypt -pkeyopt rsa_padding_mode:pkcs1 -in test.txt.enc.bin -inkey private.pem -out test.txt.dec.txt");
		S();
		ST("::加密和解密，填充方式：OAEP+SHA256，掩码生成函数MGF1使用相同的hash算法"
		 , "::Encryption and decryption, padding mode: OAEP+SHA256, mask generation function MGF1 uses the same hash algorithm");
		S("openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in test.txt -pubin -inkey public.pem -out test.txt.enc.bin");
		S("openssl pkeyutl -decrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in test.txt.enc.bin -inkey private.pem -out test.txt.dec.txt");
		S();
		S();
		ST("::命令行参数中的sha256可以换成md5、sha1等；如需sha3系列，就换成sha3-256即可"
		 , "::The sha256 in the command line parameters can be replaced by md5, sha1, etc.; if you need the sha3 series, you can replace it with sha3-256");
		S();
		S();
		ST("::签名和验证，填充方式：PKCS1+SHA256","::Signature and verification, padding mode: PKCS1+SHA256");
		S("openssl dgst -sha256 -binary -sign private.pem -out test.txt.sign.bin test.txt");
		S("openssl dgst -sha256 -binary -verify public.pem -signature test.txt.sign.bin test.txt");
		S();
		ST("::签名和验证，填充方式：PSS+SHA256 ，salt=-1使用hash长度=256/8，掩码生成函数MGF1使用相同的hash算法"
		, "::Signature and verification, padding mode: PSS+SHA256, salt=-1 use hash length=256/8, mask generation function MGF1 uses the same hash algorithm");
		S("openssl dgst -sha256 -binary -out test.txt.hash test.txt");
		S("openssl pkeyutl -sign -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -in test.txt.hash -inkey private.pem -out test.txt.sign.bin");
		S("openssl pkeyutl -verify -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -in test.txt.hash -pubin -inkey public.pem -sigfile test.txt.sign.bin");
		S();
		S();
	}
	

	
	
	static boolean waitAnyKey=true;
	static void ShowMenu(String[] args) throws Exception {
		if(args!=null && args.length>0) {
			for(String v : args) {
				if(v.startsWith("-zh=")) {
					RSA_PEM.SetLang(v.startsWith("-zh=1")?"zh":"en");
				}
			}
			S(args.length+T("个启动参数：", " startup parameters: ")+String.join(" ", args));
			S();
		}
		
		boolean newRun=true;
		while(true) {
			if(newRun) {
				newRun=false;
				S("======  https://github.com/xiangyuecn/RSA-java  ======");
				printEnv();
				S(HR);
			}
			
			boolean isSet=loadKeyFile.length()>0 && loadSrcFile.length()>0;
			String setTips=isSet?"":"        "+T("[不可用]请先设置4、5","[Unavailable] Please set 4, 5 first") + "  ";
			String floadTips=T("[已加载，修改后需重新加载]","[loaded, need to reload after modification]");
			String fileName=loadSrcFile.length()>0?new File(loadSrcFile).getName():"test.txt";
			
			S(T("【功能菜单】","[ Menu ]")+"    Java Version: "+System.getProperty("java.version")+" | "+System.getProperty("os.name"));
			S("1. "+T("测试：运行基础功能测试（1次）","Test: Run basic functional tests (1 time)"));
			S("2. "+T("测试：运行基础功能测试（1000次）","Test: Run basic functional tests (1000 times)"));
			S("3. "+T("测试：多线程并发调用同一个RSA","Test: Multiple threads call the same RSA concurrently"));
			S(HR);
			S("4. "+T("设置：加载密钥PEM文件","Setup: Load key PEM file")+(loadKeyFile.length()>0?"  "+floadTips+new File(loadKeyFile).getName()+" "+loadKey.keySize()+" bits":""));
			S("5. "+T("设置：加载目标源文件","Setup: Load Target Source File")+(loadSrcFile.length()>0?"   "+floadTips+fileName+" "+loadSrcBytes.length+" Bytes":""));
			S("6. "+T("加密    ","Encrypt")+setTips+"  "+fileName+" -> "+fileName+".enc.bin");
			S("7. "+T("解密对比","Decrypt")+setTips+"  "+fileName+".enc.bin -> "+fileName+".dec.txt");
			S("8. "+T("签名    ","Sign   ")+setTips+"  "+fileName+" -> "+fileName+".sign.bin");
			S("9. "+T("验证签名","Verify ")+setTips+"  "+fileName+".sign.bin");
			S(HR);
			S("A. "+T("RSA密钥工具：生成密钥、转换密钥格式","RSA key tool: generate key, convert key format"));
			S("B. "+T("显示当前环境支持的加密和签名填充模式，输入 B2 可同时对比OpenSSL结果", "Display the encryption and signature padding modes supported by the current environment, enter B2 to compare OpenSSL results at the same time")
				+"   ("+(CanLoad_BouncyCastle()?(BcProvider==null?
					T("可注册BouncyCastle加密增强包","Can register BouncyCastle encryption enhancement package")
					:T("已注册BouncyCastle加密增强包","BouncyCastle encryption enhancement package registered")
				):T("未检测到BouncyCastle的jar加密增强包","BouncyCastle's jar encryption enhancement package was not detected"))+")");
			S("C. "+T("显示OpenSSL中RSA相关的命令行调用命令","Display RSA-related command line calls in OpenSSL"));
			S("*. "+T("输入 exit 退出，输入 lang=zh|en 切换显示语言","Enter exit to exit, enter lang=zh|en to switch display language"));
			S();
			ST("请输入菜单序号：","Please enter the menu number:");
			System.out.print("> ");
			
			waitAnyKey=true;
			while(true) {
				String inTxt=ReadIn().trim().toUpperCase();
				
				try {
					if(inTxt.equals("1")) {
						RSATest(false);
					} else if(inTxt.equals("2")) {
						for(int i=0;i<1000;i++){ST("第"+i+"次>>>>>",i+"th time>>>>>"); RSATest(true); }
					} else if(inTxt.equals("3")) {
						waitAnyKey=false;
						threadRun();
					} else if(inTxt.equals("4")) {
						waitAnyKey=false;
						setLoadKey();
					} else if(inTxt.equals("5")) {
						waitAnyKey=false;
						setLoadSrcBytes();
					} else if(isSet && inTxt.equals("6")) {
						boolean next=setEncType();
						if(next) {
							execEnc();
						}
					} else if(isSet && inTxt.equals("7")) {
						boolean next=setEncType();
						if(next) {
							execDec();
						}
					} else if(isSet && inTxt.equals("8")) {
						boolean next=setSignType();
						if(next) {
							execSign();
						}
					} else if(isSet && inTxt.equals("9")) {
						boolean next=setSignType();
						if(next) {
							execVerify();
						}
					} else if(inTxt.equals("A")) {
						waitAnyKey=false;
						keyTools();
					} else if(inTxt.equals("B") || inTxt.equals("B2")) {
						testProvider(inTxt.equals("B2"));
					} else if(inTxt.equals("C")) {
						showOpenSSLTips();
					} else if(inTxt.startsWith("LANG=")) {
						waitAnyKey=false; newRun=true;
						if(inTxt.equals("LANG=ZH")) {
							RSA_PEM.SetLang("zh");
							S("已切换语言成简体中文");
						}else if(inTxt.equals("LANG=EN")) {
							RSA_PEM.SetLang("en");
							S("Switched language to English-US");
						}else {
							waitAnyKey=true; newRun=false;
							ST("语言设置命令无效！","Invalid language setting command!");
						}
					} else if(inTxt.equals("EXIT")) {
						S("bye!");
						return;
					} else {
						inTxt="";
						ST("序号无效，请重新输入菜单序号！","The menu number is invalid, please re-enter the menu number!");
						System.out.print("> ");
						continue;
					}
				} catch(Exception e) {
					e.printStackTrace();
					Thread.sleep(100);
					waitAnyKey=true;
				}
				break;
			}
			
			if(waitAnyKey) {
				ST("按回车键继续...","Press Enter to continue...");
				ReadIn();
			}
			S();
		}
	}
	
}
