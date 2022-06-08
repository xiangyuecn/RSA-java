package com.github.xiangyuecn.rsajava;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import javax.crypto.Cipher;


/**
 * RSA操作封装
 * 
 * GitHub:https://github.com/xiangyuecn/RSA-java
 */
public class RSA_Util {
	/**
	 * 导出XML格式密钥对，如果convertToPublic含私钥的RSA将只返回公钥，仅含公钥的RSA不受影响
	 */
	public String ToXML(boolean convertToPublic) {
		return ToPEM(convertToPublic).ToXML(convertToPublic);
	}
	/**
	 * 将密钥对导出成PEM对象，如果convertToPublic含私钥的RSA将只返回公钥，仅含公钥的RSA不受影响
	 */
	public RSA_PEM ToPEM(boolean convertToPublic) {
		return new RSA_PEM(publicKey, convertToPublic?null:privateKey);
	}
	
	
	
	
	/**
	 * 加密字符串（utf-8），出错抛异常
	 */
	public String Encode(String str) throws Exception {
		return Base64.getEncoder().encodeToString(Encode(str.getBytes("utf-8")));
	}
	/**
	 * 加密数据，出错抛异常
	 */
	public byte[] Encode(byte[] data) throws Exception {
		try(ByteArrayOutputStream stream=new ByteArrayOutputStream()){
			Cipher enc = Cipher.getInstance("RSA");
			enc.init(Cipher.ENCRYPT_MODE, publicKey);
			int blockLen = keySize / 8 - 11;
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
	 * 解密字符串（utf-8），出错抛异常
	 */
	public String Decode(String str) throws Exception {
		if (str==null || str.length()==0) {
			return "";
		}
		byte[] byts = Base64.getDecoder().decode(str);
		byte[] val = Decode(byts);
		return new String(val, "utf-8");
	}
	/**
	 * 解密数据，出错抛异常
	 */
	public byte[] Decode(byte[] data) throws Exception {
		try(ByteArrayOutputStream stream=new ByteArrayOutputStream()){
			Cipher dec = Cipher.getInstance("RSA");
			dec.init(Cipher.DECRYPT_MODE, privateKey);
			int blockLen = keySize / 8;
			int start=0;
			while(start<data.length) {
				int len=blockLen;
				if(start+len>data.length) {
					len=data.length-start;
				}
				
				byte[] de = dec.doFinal(data, start, len);
				stream.write(de);
				start+=len;
			}
			
			return stream.toByteArray();
		}
	}
	/**
	 * 对str进行签名，并指定hash算法（如：SHA256 大写），出错抛异常
	 */
	public String Sign(String hash, String str) throws Exception {
		return Base64.getEncoder().encodeToString(Sign(hash, str.getBytes("utf-8")));
	}
	/**
	 * 对data进行签名，并指定hash算法（如：SHA256 大写），出错抛异常
	 */
	public byte[] Sign(String hash, byte[] data) throws Exception {
		Signature signature=Signature.getInstance(hash+"WithRSA");
		signature.initSign(privateKey);
		signature.update(data);
		return signature.sign();
	}
	/**
	 * 验证字符串str的签名是否是sign，并指定hash算法（如：SHA256 大写），出错抛异常
	 */
	public boolean Verify(String hash, String sign, String str) throws Exception {
		byte[] byts = Base64.getDecoder().decode(sign);
		return Verify(hash, byts, str.getBytes("utf-8"));
	}
	/**
	 * 验证data的签名是否是sign，并指定hash算法（如：SHA256 大写）
	 */
	public boolean Verify(String hash, byte[] sign, byte[] data) throws Exception {
		Signature signVerify=Signature.getInstance(hash+"WithRSA");
		signVerify.initVerify(publicKey);
		signVerify.update(data);
		return signVerify.verify(sign);
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
}
