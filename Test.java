package com.github.xiangyuecn.rsajava;

/**
 * RSA_PEM测试控制台主程序
 * 
 * GitHub:https://github.com/xiangyuecn/RSA-java
 */
public class Test {
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
		
		System.out.println("【" + rsa.keySize() + "私钥（XML）】：");
		System.out.println(xml);
		System.out.println();
		System.out.println("【" + rsa.keySize() + "私钥（PKCS#1）】：");
		System.out.println(pem_pkcs1);
		System.out.println();
		System.out.println("【" + rsa.keySize() + "公钥（PKCS#8）】：");
		System.out.println(pem.ToPEM_PKCS8(true));
		System.out.println();
		
		
		String str = "abc内容123";
		String en=rsa.Encode(str);
		System.out.println("【加密】：");
		System.out.println(en);
		
		System.out.println("【解密】：");
		String de=rsa.Decode(en);
		AssertMsg(de, de.equals(str));
		
		if (!fast) {
			String str2 = str; for (int i = 0; i < 15; i++) str2 += str2;
			System.out.println("【长文本加密解密】：");
			AssertMsg(str2.length() + "个字 OK", rsa.Decode(rsa.Encode(str2)).equals(str2));
		}
		
		
		System.out.println("【签名SHA1】：");
		String sign = rsa.Sign("SHA1", str);
		System.out.println(sign);
		AssertMsg("校验 OK", rsa.Verify("SHA1", sign, str));
		System.out.println();
		
		
		
		//用pem文本创建RSA
		RSA_Util rsa2=new RSA_Util(RSA_PEM.FromPEM(pem_pkcs8));
		RSA_PEM pem2=rsa2.ToPEM(false);
		System.out.println("【用PEM新创建的RSA是否和上面的一致】：");
		Assert("XML：", pem2.ToXML(false) .equals( pem.ToXML(false) ));
		Assert("PKCS1：", pem2.ToPEM_PKCS1(false) .equals( pem.ToPEM_PKCS1(false) ));
		Assert("PKCS8：", pem2.ToPEM_PKCS8(false) .equals( pem.ToPEM_PKCS8(false) ));
		
		//用xml文本创建RSA
		RSA_Util rsa3=new RSA_Util(RSA_PEM.FromXML(xml));
		RSA_PEM pem3=rsa3.ToPEM(false);
		System.out.println("【用XML新创建的RSA是否和上面的一致】：");
		Assert("XML：", pem3.ToXML(false) .equals( pem.ToXML(false) ));
		Assert("PKCS1：", pem3.ToPEM_PKCS1(false) .equals( pem.ToPEM_PKCS1(false) ));
		Assert("PKCS8：", pem3.ToPEM_PKCS8(false) .equals( pem.ToPEM_PKCS8(false) ));
		
		
		//--------RSA_PEM私钥验证---------
		//使用PEM全量参数构造pem对象
		RSA_PEM pemX = new RSA_PEM(pem.Key_Modulus, pem.Key_Exponent, pem.Key_D
			, pem.Val_P, pem.Val_Q, pem.Val_DP, pem.Val_DQ, pem.Val_InverseQ);
		System.out.println("【RSA_PEM是否和原始RSA一致】：");
		System.out.println(pemX.keySize() + "位");
		Assert("XML：", pemX.ToXML(false) .equals( pem.ToXML(false) ));
		Assert("PKCS1：", pemX.ToPEM_PKCS1(false) .equals( pem.ToPEM_PKCS1(false) ));
		Assert("PKCS8：", pemX.ToPEM_PKCS8(false) .equals( pem.ToPEM_PKCS8(false) ));
		System.out.println("仅公钥：");
		Assert("XML：", pemX.ToXML(true) .equals( pem.ToXML(true) ));
		Assert("PKCS1：", pemX.ToPEM_PKCS1(true) .equals( pem.ToPEM_PKCS1(true) ));
		Assert("PKCS8：", pemX.ToPEM_PKCS8(true) .equals( pem.ToPEM_PKCS8(true) ));
		
		//--------RSA_PEM公钥验证---------
		RSA_PEM pemY = new RSA_PEM(pem.Key_Modulus, pem.Key_Exponent, null);
		System.out.println("【RSA_PEM仅公钥是否和原始RSA一致】：");
		System.out.println(pemY.keySize() + "位");
		Assert("XML：", pemY.ToXML(false) .equals( pem.ToXML(true) ));
		Assert("PKCS1：", pemY.ToPEM_PKCS1(false) .equals( pem.ToPEM_PKCS1(true) ));
		Assert("PKCS8：", pemY.ToPEM_PKCS8(false) .equals( pem.ToPEM_PKCS8(true) ));
		
		
		if (!fast) {
			//使用n、e、d构造pem对象
			RSA_PEM pem4 = new RSA_PEM(pem.Key_Modulus, pem.Key_Exponent, pem.Key_D);
			RSA_Util rsa4=new RSA_Util(pem4);
			System.out.println("【用n、e、d构造解密】");
			de=rsa4.Decode(en);
			AssertMsg(de, de.equals(str));
		}
		
		
		
		System.out.println();
		System.out.println();
		System.out.println("【" + pem.keySize() + "私钥（PKCS#8）】：");
		System.out.println(pem.ToPEM_PKCS8(false));
		System.out.println();
		System.out.println("【" + pem.keySize() + "公钥（PKCS#1）】：不常见的公钥格式");
		System.out.println(pem.ToPEM_PKCS1(true));
	}
	
	
	
	static void Assert(String msg, boolean check) throws Exception {
		AssertMsg(msg + check, check);
	}
	static void AssertMsg(String msg, boolean check) throws Exception {
		if (!check) throw new Exception(msg);
		System.out.println(msg);
	}
	
	public static void main(String[] argv) throws Exception{
		System.out.println("---------------------------------------------------------");
		System.out.println("◆◆◆◆◆◆◆◆◆◆◆◆ RSA测试 ◆◆◆◆◆◆◆◆◆◆◆◆");
		System.out.println("---------------------------------------------------------");

		//for(int i=0;i<1000;i++){System.out.println("第"+i+"次>>>>>"); RSATest(true); }
		RSATest(false);

		System.out.println("-------------------------------------------------------------");
		System.out.println("◆◆◆◆◆◆◆◆◆◆◆◆ 测试结束 ◆◆◆◆◆◆◆◆◆◆◆◆");
	}
}
