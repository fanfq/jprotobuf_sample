package com.fcstudio.jprotobuf_sample;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.ArrayUtils;

public class AES_ECB_PKCS7Padding_Util {

	/*
	// 如果不是因为 PKCS7Padding 我都不知道这种软件算法也能收到出口管制
	// https://blog.csdn.net/lijun169/article/details/82736103
	<!-- AES_ECB_PKCS7Padding_Util -->
	<dependency>
	    <groupId>org.bouncycastle</groupId>
	    <artifactId>bcprov-jdk15</artifactId>
	    <version>[1.60,)</version>
	</dependency>
	*/

	

	// 填充类型
	public static final String AES_TYPE = "AES/ECB/PKCS7Padding";

	static {
		if (Security.getProvider("BC") == null) {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		} else {
			Security.removeProvider("BC");
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		}
	}

	private static byte[] encrypt(byte[] data,String AES_KEY) {
		try {
			SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(), "AES");
			Cipher cipher = Cipher.getInstance(AES_TYPE, "BC");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private static byte[] decrypt(byte[] data,String AES_KEY) {
		try {
			SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(), "AES");
			Cipher cipher = Cipher.getInstance(AES_TYPE, "BC");
			cipher.init(Cipher.DECRYPT_MODE, key);
			return cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}
	
	/**
	 * 协议body数据, 先将最后一个字节取出，记为mod_len， 然后将body截掉尾部16字节填充数据块后再解密（与加密填充额外数据块逻辑对应）
	 * mod_len 为0时，上述解密后的数据即为协议返回的body数据, 否则需截掉尾部(16 - mod_len)长度的用于填充对齐的数据
	 * @param data
	 * @return
	 */
	public static byte[] decode(byte[] data,String AES_KEY) {
		//分离最后16个字节数组，并取出modlen
		byte[] bodyArray = ArrayUtils.subarray(data, 0, data.length-16);
		int modLen = ArrayUtils.subarray(data, data.length-1, data.length)[0] & 0xFF;
		byte[] bodyDecode = decrypt(bodyArray,AES_KEY);
		
		return ArrayUtils. subarray(bodyDecode,0,bodyDecode.length-(16-modLen));
	}
	
	/**
	 * AES加密要求源数据长度必须是16的整数倍, 故需补‘0’对齐后再加密，记录mod_len为源数据长度与16取模值
	 * 因加密前有可能对源数据作修改， 故需在加密后的数据尾再增加一个16字节的填充数据块，其最后一个字节赋值mod_len, 其余字节赋值‘0’， 将加密数据和额外的填充数据块拼接作为最终要发送协议的body数据
	 * @param data
	 * @return
	 */
	public static byte[] encode(byte[] data,String AES_KEY) {
		byte[] block = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//16个字节一组
		int blockLen = block.length;
		byte[] retArray;
		int len = data.length;
		int modLen = len%blockLen;
		
		if(modLen == 0) {
			//源字节数组刚好是16的整倍数，
			retArray = data;
		}else {
			int capLen = blockLen -modLen;//需要补偿的字节个数
			byte[] capArray = ArrayUtils.subarray(block, 0, capLen);//截取需要补偿的字节
			retArray = ArrayUtils.addAll(data, capArray);//将其补充到源字节数组的尾部并返回新的字节数组
		}
		//加密
		byte[] encodedArray = encrypt(retArray,AES_KEY);
		
		//根据modLen再补16个字节,最后一个字节为modLen
		byte[] modArray = {(byte)modLen};
		byte[] lastArray = ArrayUtils.addAll(ArrayUtils.subarray(block, 0, blockLen-1),modArray);
		
		//返回加密数据 + 最后一行补充数据
		return ArrayUtils.addAll(encodedArray,lastArray);
	}
	
	private static void pf(byte[] data) {
		String x2 = "";
        for (byte b : data) {
            x2 += b + ",";
        }
        System.out.println(x2.substring(0, x2.length() - 1)+"\nlen:"+ data.length+"\n");
	}
	
	public static void main(String[] args) {
		// 私钥 //AES固定格式为128/192/256 bits.即：16/24/32bytes。DES固定格式为128bits，即8bytes。
		String AES_KEY = "1111222233334444";
		
		byte[] src = {1,0,0,0,0,0,0,0,2,-124,108,117,52,-111,123,72,107,-95,119,-84,41,-92,48,30,-67,-25,124,49,-24,26};
		byte[] s = encode(src,AES_KEY);
		
		System.out.println("源：");
		pf(src);
		
		System.out.println("AES/ECB/PKCS5Padding 加密：");
		pf(s);
		
		
		System.out.println("AES/ECB/PKCS5Padding 解密：");
		byte[] ss = decode(s,AES_KEY);
		pf(ss);
	}

}
