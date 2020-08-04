package com.fcstudio.jprotobuf_sample;

import javax.crypto.Cipher;

import org.apache.commons.lang.ArrayUtils;

public class RSA_1024_ECB_PKCS1Padding_Util {
	
	/*
	 * 可到”http://web.chacuo.net/netrsakeypair“这个网址在线生成随机RSA密钥对
	 * 密钥长度1024, 填充方式PKCS1,公钥加密，私钥解密，公钥可通过私钥生成
	 */
	
	private static final String privateKey_ = "-----BEGIN RSA PRIVATE KEY-----\n" + 
			"MIICXQIBAAKBgQCjWH71BXC8aU+gm4Jo4A2c88tqG/TOaIp5sURXlp6X7boOJ444\n" + 
			"WxtJbv7kaA14RglvmggDgY04YfoF8a/WQucnssJxlVYdDr5Iv0OyHtDGmsIdKPCk\n" + 
			"7d2AwVHTe/3ggOfTUm8uoDBrOB18FdeLliqNmcuNxfqKWrmJvqy6ISxEbwIDAQAB\n" + 
			"AoGAHkRGFgGhj4/V7NUT13n4m8YCwZEXje2KBx2FI9OpZE5s5LWIoUGkbzltaoYr\n" + 
			"RMd5dR/t7zRgpftlmBdd9Q4lhYWPJiVZressfZHw52GJVaeJRkrNrnMZtapi8T/J\n" + 
			"LGtVkeHHly7f9903llClBHDQvozu0bOiPZ+dbRqFhKMqHjECQQCxuyxJxTf/D9wa\n" + 
			"POY3VW9ITlcON16Dy12pryihfMr22NcAAhwqZ51VIWS9vbCwRaAZtI8hJW17OPBk\n" + 
			"D/mM5fWfAkEA60eNuEO4ormSO+Jp/mHMEpv1UyCL9JTuFN8avMVR3PM/q04ddxlJ\n" + 
			"kP2DdFJfP+Lao7LjOo15K3T9POq1E1YfMQJAPBc6nB6QFi64ji5079R08Y97I5VY\n" + 
			"4VqK6moMZL0aqmcaGiiceUHbEgNeWkCeUprXzJkdo2lSIM1ZiZtVFmxRpQJBAIWS\n" + 
			"C7zuhWWsYH6q3W3Ta52s+KuGsK3b1wX2WyGMDBuZ5S2FnWi97Gvp4LUrBnQof+Or\n" + 
			"bSESrBWlxxbMUJx3qiECQQCBcY3xl0OKsXoVvk5keI4mEPsNyd6Bl5SxmxR2ZRgl\n" + 
			"FgQlKY58yxaokvC5uDqnSWwaP6iKQ1nilownxsrSZLqf\n" + 
			"-----END RSA PRIVATE KEY-----";
	
	/**
	 * RSA加密规则:若密钥位数是key_size, 单次加密串的最大长度为 (key_size)/8 - 11, 目前位数1024, 一次加密长度可定为100
	 * 将明文数据分成一个或数个最长100字节的小段进行加密，拼接分段加密数据即为最终的Body加密数据
	 * 《RSA密钥长度、明文长度和密文长度》详解
	 * https://www.cnblogs.com/Dennis-mi/articles/6235832.html
	 * @param data
	 * @return
	 */
	public static byte[] encode(byte[] data) {
		try {
			// 使用PEM PKCS#1文件的文本构造出pem对象
			RSA_PEM pem = RSA_PEM.FromPEM(privateKey_);
			pem.ToPEM_PKCS1(false);
//			boolean isEqRaw=pem.ToPEM_PKCS1(false).replaceAll("\\r|\\n","").equals(privateKey_.replaceAll("\\r|\\n",""));
//			System.out.println("【" + pem.keySize() + "私钥（PKCS#1）】：是否和KeyPair生成的相同"+(isEqRaw));
			
			Cipher enc = Cipher.getInstance("RSA");
			enc.init(Cipher.ENCRYPT_MODE, pem.getRSAPublicKey());

			int blockLen = 100;// 分组加密，每组100个字节
			byte[] buffers = new byte[] {};
			for (int i = 0; i < data.length; i += blockLen) {
				byte[] subarray = ArrayUtils.subarray(data, i, i + blockLen);
				byte[] en = enc.doFinal(subarray);
				buffers = ArrayUtils.addAll(buffers, en);
			}
			return buffers;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * 接收数据解密:
     * RSA解密同样遵循分段规则，对于1024位密钥, 每小段待解密数据长度为128字节
     * 将密文数据分成一个或数个128字节长的小段进行解密，拼接分段解密数据即为最终的Body解密数据
	 * @param data
	 * @return
	 */
	public static byte[] decode(byte[] data) {
		try {
			RSA_PEM pem = RSA_PEM.FromPEM(privateKey_);
			Cipher dec = Cipher.getInstance("RSA");
			dec.init(Cipher.DECRYPT_MODE, pem.getRSAPrivateKey());
			int blockLen = 128;// 分组解密，每组128个字节
			byte[] buffers = new byte[] {};
			for (int i = 0; i < data.length; i += blockLen) {
				byte[] subarray = ArrayUtils.subarray(data, i, i + blockLen);
				byte[] de = dec.doFinal(subarray);
				buffers = ArrayUtils.addAll(buffers, de);
			}
			return buffers;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private static void pf(byte[] data) {
		String x2 = "";
        for (byte b : data) {
            x2 += b + ",";
        }
        System.out.println(x2.substring(0, x2.length() - 1)+"\nlen:"+ data.length+"\n");
	}
	
	public static void main(String[] args) {
		byte[] src = {49,-105,48,107,17,-25,-82,121,-44,8,87,-123,-13,76,-47,83,114,-72,-11,121,92,79,9,29,-90,91,-90,-102,-122,118,-120,-6,-47,-48,12,-11,-111,-114,-87,-53,-56,-102,-36,74,-87,-1,17,-8,104,-116,-95,-18,122,-77,122,-31,125,-70,44,-4,86,121,47,-19,-43,-2,-42,30,18,37,124,-55,109,103,11,13,79,-62,44,-51,32,-121,75,59,54,101,101,-104,14,-48,-19,61,-81,-27,-18,-63,25,20,-26,-102,-123,116,-57,106,71,68,103,12,13,5,44,37,-45,90,-45,-71,-51,-55,-63,78,98,-61,-34,-71,-2,26,88,-106
,1,0,0,0,0,0,0,0,2,-124,108,117,52,-111,123,72,107,-95,119,-84,41,-92,48,30,-67,-25,124,49,-24,26};
		byte[] s = encode(src);
		
		System.out.println("源：");
		pf(src);
		
		System.out.println("RSA_1024_ECB_PKCS1Padding_Util 加密：");
		pf(s);
		
		
		System.out.println("RSA_1024_ECB_PKCS1Padding_Util 解密：");
		byte[] ss = decode(s);
		pf(ss);
	}

}
