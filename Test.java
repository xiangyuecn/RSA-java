package com.github.xiangyuecn.rsajava;

import javax.crypto.Cipher;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

/**
 * RSA_PEM测试控制台主程序
 * 
 * GitHub:https://github.com/xiangyuecn/RSA-java
 */
public class Test {
	static void RSATest() throws Exception{
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(512,new SecureRandom());
		KeyPair keyPair = keygen.generateKeyPair();
		
		String pemRawTxt=""
			+"-----BEGIN PRIVATE KEY-----"
			+Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded())
			+"-----END PRIVATE KEY-----";
		RSA_PEM pem=RSA_PEM.FromPEM(pemRawTxt);
		
		boolean isEqRaw=pem.ToPEM(false,true).replaceAll("\\r|\\n","").equals(pemRawTxt);
		
		System.out.println("【" + pem.keySize() + "私钥（XML）】：");
		System.out.println(pem.ToXML(false));
		System.out.println();
		System.out.println("【" + pem.keySize() + "私钥（PEM）】：是否和KeyPair生成的相同"+(isEqRaw));
		System.out.println(pem.ToPEM(false,false));
		System.out.println();
		System.out.println("【" + pem.keySize() + "公钥（PEM）】：");
		System.out.println(pem.ToPEM(true,false));
		System.out.println();
		
		
		String str = "abc内容123";
		
		Cipher enc = Cipher.getInstance("RSA");
		enc.init(Cipher.ENCRYPT_MODE, pem.getRSAPublicKey());
		byte[] en = enc.doFinal(str.getBytes("utf-8"));
		
		Cipher dec = Cipher.getInstance("RSA");
		dec.init(Cipher.DECRYPT_MODE, pem.getRSAPrivateKey());
		byte[] de = dec.doFinal(en);
		
		System.out.println("【加密】：");
		System.out.println(Base64.getEncoder().encodeToString(en));

		System.out.println("【解密】：");
		System.out.println(new String(de,"utf-8"));
		
		
		//TODO 签名、校验有时间在写
		System.out.println();
		
		
		
		RSA_PEM pem2=RSA_PEM.FromPEM(pem.ToPEM(false,true));
		System.out.println("【用PEM新创建的RSA是否和上面的一致】：");
		System.out.println("XML：" + (pem2.ToXML(false) .equals( pem.ToXML(false) )));
		System.out.println("PKCS1：" + (pem2.ToPEM(false,false) .equals( pem.ToPEM(false,false) )));
		System.out.println("PKCS8：" + (pem2.ToPEM(false,true) .equals( pem.ToPEM(false,true) )));
		
		RSA_PEM pem3=RSA_PEM.FromXML(pem.ToXML(false));
		System.out.println("【用XML新创建的RSA是否和上面的一致】：");
		System.out.println("XML：" + (pem3.ToXML(false) .equals( pem.ToXML(false) )));
		System.out.println("PKCS1：" + (pem3.ToPEM(false,false) .equals( pem.ToPEM(false,false) )));
		System.out.println("PKCS8：" + (pem3.ToPEM(false,true) .equals( pem.ToPEM(false,true) )));
		
		
		//--------RSA_PEM验证---------
		RSA_PEM pemX = new RSA_PEM(pem.Key_Modulus, pem.Key_Exponent, pem.Key_D
			, pem.Val_P, pem.Val_Q, pem.Val_DP, pem.Val_DQ, pem.Val_InverseQ);
		System.out.println("【RSA_PEM是否和原始RSA一致】：");
		System.out.println(pem.keySize() + "位");
		System.out.println("XML：" + (pemX.ToXML(false) .equals( pem.ToXML(false) )));
		System.out.println("PKCS1：" + (pemX.ToPEM(false, false) .equals( pem.ToPEM(false, false) )));
		System.out.println("PKCS8：" + (pemX.ToPEM(false, true) .equals( pem.ToPEM(false, true) )));
		System.out.println("仅公钥：");
		System.out.println("XML：" + (pemX.ToXML(true) .equals( pem.ToXML(true) )));
		System.out.println("PKCS1：" + (pemX.ToPEM(true, false) .equals( pem.ToPEM(true, false) )));
		System.out.println("PKCS8：" + (pemX.ToPEM(true, true) .equals( pem.ToPEM(true, true) )));
		
		RSA_PEM pem4 = new RSA_PEM(pem.Key_Modulus, pem.Key_Exponent, pem.Key_D);
		Cipher dec4 = Cipher.getInstance("RSA");
		dec4.init(Cipher.DECRYPT_MODE, pem4.getRSAPrivateKey());
		System.out.println("【用n、e、d构造解密】");
		System.out.println(new String(dec4.doFinal(en),"utf-8"));
	}
	
	
	
	
	
	public static void main(String[] argv) throws Exception{
		System.out.println("---------------------------------------------------------");
		System.out.println("◆◆◆◆◆◆◆◆◆◆◆◆ RSA测试 ◆◆◆◆◆◆◆◆◆◆◆◆");
		System.out.println("---------------------------------------------------------");

		RSATest();

		System.out.println("-------------------------------------------------------------");
		System.out.println("◆◆◆◆◆◆◆◆◆◆◆◆ 测试结束 ◆◆◆◆◆◆◆◆◆◆◆◆");
	}
}