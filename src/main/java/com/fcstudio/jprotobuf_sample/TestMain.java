package com.fcstudio.jprotobuf_sample;

import com.alibaba.fastjson.JSON;
import com.baidu.bjf.remoting.protobuf.Codec;
import com.baidu.bjf.remoting.protobuf.ProtobufProxy;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import lombok.extern.slf4j.Slf4j;

import java.io.*;

/**
 * @program: jprotobuf_sample
 * @description:
 * @author: fangqing.fan#hotmail.com
 * @create: 2020-07-31 22:24
 *
 * https://github.com/jhunters/jprotobuf
 **/

@Slf4j
public class TestMain {

    public static void main(String[] args) {
        Codec<Message> codec = ProtobufProxy.create(Message.class);

        Message msg = new Message();
        msg.setName("zhangsan123..jju");
        msg.setValue(1024);

        try {
            String body = JSON.toJSONString(msg);
            log.warn("body源:{}", body);


            log.warn("********************jprotobuf");
            //序列化
            byte[] bb = codec.encode(msg);
            log.debug("jprotobuf序列化");
            pf(bb);

            //反序列化
            Message newMsg = codec.decode(bb);
            log.info("jprotobuf反序列化：{}", JSON.toJSONString(newMsg));

            log.warn("********************消息头  bodylen(4byte) | remote(2byte) | method (2byte)");

            byte[] jEncode = jProtobufEncode((short) 1, (short) 2, bb);
            log.debug("jprotobuf序列化，包含消息头");
            pf(jEncode);

            byte[] jDecode = jProtobufDecode(jEncode);
            log.debug("jprotobuf反序列化，解消息头,{}",JSON.toJSONString(codec.decode(jDecode)));
            pf(jDecode);


            log.warn("截止到这里常规的做法就结束了，下面开始加密处理********************");
            log.warn("********************rsa");

            log.debug("jprotobuf序列化,后并通过RSA_1024_ECB_PKCS1Padding加密");
            log.warn("rsa 加密:序列化->加密获取body—>加消息头：{}");
            byte[] rsa = RSA_1024_ECB_PKCS1Padding_Util.encode(bb);
            pf(rsa);
            jEncode = jProtobufEncode((short) 1, (short) 2, rsa);
            log.debug("jprotobuf序列化,后并通过RSA_1024_ECB_PKCS1Padding加密，包含消息头 [可发送数据]");
            pf(jEncode);


            jDecode = jProtobufDecode(jEncode);
            log.warn("rsa 解密:解头获取body->解密获取原文->反序列化：{}",JSON.toJSONString(codec.decode(RSA_1024_ECB_PKCS1Padding_Util.decode(jDecode))));
            pf(jDecode);

            log.warn("********************aes");
            String AES_KEY = "1111222233334444";
            log.warn("aes 加密:序列化->加密获取body—>加消息头：{}");
            byte[] aes = AES_ECB_PKCS7Padding_Util.encode(bb,AES_KEY);
            pf(aes);
            jEncode = jProtobufEncode((short) 1, (short) 2, aes);
            log.debug("jprotobuf序列化,后并通过AES_ECB_PKCS7Padding加密，包含消息头 [可发送数据]");
            pf(jEncode);

            jDecode = jProtobufDecode(jEncode);
            log.warn("aes 解密:解头获取body->解密获取原文->反序列化：{}",JSON.toJSONString(codec.decode(AES_ECB_PKCS7Padding_Util.decode(jDecode,AES_KEY))));
            pf(jDecode);


        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private static byte[] jProtobufEncode(short remote, short method, byte[] data) {
        ByteBuf buffer = Unpooled.buffer();

        buffer.alloc();
        buffer.writeInt(data.length);
        buffer.writeShort(remote);
        buffer.writeShort(method);
        buffer.writeBytes(data);

        return buffer.array();
    }

    private static byte[] jProtobufDecode(byte[] data) {
        ByteBuf buffer = Unpooled.wrappedBuffer(data);

        int bLen = buffer.readInt();
        short remote = buffer.readShort();
        short method = buffer.readShort();
        byte[] body = new byte[bLen];
        buffer.readBytes(body);

        return body;
    }


    private static String readFile(String fileName) {
        StringBuffer sb = new StringBuffer();
        try {
            File file = new File(TestMain.class.getClassLoader().getResource("").getPath() + fileName);
            InputStreamReader read = new InputStreamReader(new FileInputStream(file));
            BufferedReader br = new BufferedReader(read);
            String line = br.readLine();
            while (line != null) {
                sb.append(line);
                line = br.readLine();
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return sb.toString();
    }


    private static void pf(byte[] bbuf) {
        String x2 = "";
        for (byte b : bbuf) {
            x2 += b + ",";
        }
        log.info("data：{}  len:{}", x2.substring(0, x2.length() - 1), bbuf.length);
    }


    /**
     * 指定加密算法为RSA
     */
    private static final String ALGORITHM = "RSA";
    /**
     * 指定公钥存放文件
     */
    private static String PUBLIC_KEY_FILE = "rsa_1024_pkcs1_public.key";
    /**
     * 指定私钥存放文件
     */
    private static String PRIVATE_KEY_FILE = "rsa_1024_pkcs1_private.key";

}