package com.starscube.ecps.core.common.util;

import com.starscube.ecps.core.common.Constants;
import com.sun.xml.internal.messaging.saaj.util.ByteInputStream;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.io.pem.PemObject;

import javax.crypto.Cipher;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
/**
 * @Author wind
 * @Description RSA加解密以及签名和验签
 * @Date 15:24 2018/9/18
 * @Param
 * @return
 **/
public class RsaUtilsNew {

    public static final String PEM_PUBLICKEY = "PUBLIC KEY";

    public static final String PEM_PRIVATEKEY = "PRIVATE KEY";


    /**
     * 初始化密钥
     *
     * @return
     * @throws Exception
     */
    public static Map<String, Key> initKey() throws Exception {
        KeyPairGenerator keyPairGen;
        keyPairGen = KeyPairGenerator.getInstance(Constants.KEY_ALGORITHM);
        keyPairGen.initialize(1024);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        //ContextMap.publicKey.setPublicKey((RSAPublicKey) keyPair.getPublic());
        //ContextMap.privateKey.setPrivateKey((RSAPrivateKey) keyPair.getPrivate());
        Map<String, Key> keyMap = new HashMap<String, Key>(2);
        keyMap.put(Constants.PUBLIC_KEY, keyPair.getPublic());// 公钥
        keyMap.put(Constants.PRIVATE_KEY, keyPair.getPrivate());// 私钥
        return keyMap;
    }


    public static String convertToPemKey(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        if (publicKey == null && privateKey == null) {
            return null;
        }
        StringWriter stringWriter = new StringWriter();
        PEMWriter pemWriter = null;
        try {
            pemWriter = new PEMWriter(stringWriter, "BC");

            if (publicKey != null) {

                pemWriter.writeObject(new PemObject(PEM_PUBLICKEY, publicKey.getEncoded()));
            } else {
                pemWriter.writeObject(new PemObject(PEM_PRIVATEKEY, privateKey.getEncoded()));
            }
            pemWriter.flush();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (pemWriter != null) {
                try {
                    pemWriter.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return stringWriter.toString();
    }


    /**
     * @Author wind
     * @Description 将公钥字符串转换为RSA公钥对象
     * @Date 15:24 2018/9/18
     * @Param [pubKeyStr]
     * @return java.security.interfaces.RSAPublicKey
     **/
    public static RSAPublicKey loadPublicKey(String pubKeyStr) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        PEMReader reader = null;
        try {
            reader = new PEMReader(new StringReader(pubKeyStr), new PasswordFinder() {
                public char[] getPassword() {
                    return "".toCharArray();
                }
            });
            //PEMReader pemReader = new PEMReader(sr);
            RSAPublicKey keyPair = (RSAPublicKey) reader.readObject();
            return keyPair;
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }

        }
        return null;
    }

    /**
     * @Author wind
     * @Description 将私钥字符串转换位RSA私钥对象
     * @Date 15:25 2018/9/18
     * @Param [priKeyStr]
     * @return java.security.interfaces.RSAPrivateKey
     **/
    public static RSAPrivateKey loadPrivateKey(String priKeyStr) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        PEMReader reader = null;
        try {
            reader = new PEMReader(new StringReader(priKeyStr), new PasswordFinder() {
                public char[] getPassword() {
                    return "".toCharArray();
                }
            });
            //PEMReader pemReader = new PEMReader(sr);
            RSAPrivateKey keyPair = (RSAPrivateKey) reader.readObject();
            return keyPair;
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }

        }
        return null;
    }


    /**
     * @Author wind
     * @Description 使用公钥加密
     * @Date 15:25 2018/9/18
     * @Param [data, key]
     * @return String
     **/
    public static String encryptByPublicKey(String data, String key) {
        try {
            // 对公钥解密
            byte[] keyBytes = loadPublicKey(key).getEncoded();
            // 取得公钥
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(Constants.KEY_ALGORITHM);
            Key publicKey = keyFactory.generatePublic(x509KeySpec);
            // 对数据加密
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return Base64.encodeBase64String(cipher.doFinal(data.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * @Author wind
     * @Description //使用私钥解密
     * @Date 15:25 2018/9/18
     * @Param [data, key]
     * @return String
     **/
    public static String decryptByPrivateKey(String data, String key) throws Exception {
        // 对密钥解密
        byte[] keyBytes = loadPrivateKey(key).getEncoded();
        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(Constants.KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        // 对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.decodeBase64(data)),Constants.SYS_ENCODING);
    }



    /**
     * @Author wind
     * @Description //TODO 使用私钥签名
     * @Date 15:26 2018/9/18
     * @Param [data, privateKey]
     * @return String
     **/
    public static String sign(String data, String privateKey){
        try {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                    loadPrivateKey(privateKey).getEncoded());

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PrivateKey privateKey2 = keyFactory
                    .generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance(Constants.SIGNATURE_ALGORITHM);
            signature.initSign(privateKey2);
            signature.update(data.getBytes());
            return bytes2String(signature.sign());
        } catch(Exception e) {
            e.printStackTrace();
        }
        return null;

    }

    /**
     * @Author wind
     * @Description //TODO 利用公钥验证签名
     * @Date 15:26 2018/9/18
     * @Param [data, publicKey, signatureResult]
     * @return boolean
     **/
    public static boolean verify(String data, String publicKey,
                                 String signatureResult) {
        try {
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                    loadPublicKey(publicKey).getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey2 = keyFactory
                    .generatePublic(x509EncodedKeySpec);

            Signature signature = Signature.getInstance(Constants.SIGNATURE_ALGORITHM);
            signature.initVerify(publicKey2);
            signature.update(data.getBytes());

            return signature.verify(hexStringToByteArray(signatureResult));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * @Author wind
     * @Description //TODO 后台测试签名的时候 要和前台保持一致，所以需要将结果转换
     * @Date 15:27 2018/9/18
     * @Param [bytes]
     * @return java.lang.String
     **/
    public static String bytes2String(byte[] bytes) {
        StringBuilder string = new StringBuilder();
        for (byte b : bytes) {
            String hexString = Integer.toHexString(0x00FF & b);
            string.append(hexString.length() == 1 ? "0" + hexString : hexString);
        }
        return string.toString();
    }

    
    /**
     * @Author wind
     * @Description //TODO 前台的签名结果是将byte 中的一些 负数转换成了正数，但是后台验证的方法需要的又必须是转换之前的
     * @Date 15:27 2018/9/18
     * @Param [data]
     * @return byte[]
     **/
    public static byte[] hexStringToByteArray(String data) {
        int k = 0;
        byte[] results = new byte[data.length() / 2];
        for (int i = 0; i + 1 < data.length(); i += 2, k++) {
            results[k] = (byte) (Character.digit(data.charAt(i), 16) << 4);
            results[k] += (byte) (Character.digit(data.charAt(i + 1), 16));
        }
        return results;
    }


    /**
     * @Author wind
     * @Description //TODO 验证方法
     * @Date 15:27 2018/9/18
     * @Param [args]
     * @return void
     **/
    public static void main(String[] args) {
        try {
            /*Map<String, Key> map = RsaUtilsNew.initKey();

            RSAPublicKey pubKey = (RSAPublicKey) map.get(Constants.PUBLIC_KEY);
            RSAPrivateKey priKey = (RSAPrivateKey) map.get(Constants.PRIVATE_KEY);
            String pb = convertToPemKey(pubKey, null);
            String pr = convertToPemKey(null, priKey);
            System.out.println(pb);
            System.out.println(pr);*/

            String pb = "-----BEGIN PUBLIC KEY-----\n" +
                    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDoJwxlhXoEbdFgyx3xCd7x95El\n" +
                    "e53bz78m+Eqe8akDXpGcSVl4YDYea9y3A3TwjdE3JPkHDrJ89A1JRTcHSjq1ky1J\n" +
                    "jq0c1d4BKFS9sIc7Tb1cXydtZXyImPZNzTzYm+U/4LBt0Sbd1wV5it6B8fGLujZ2\n" +
                    "Phh4jcLMj4i0JYzkpwIDAQAB\n" +
                    "-----END PUBLIC KEY-----";

            String pr = "-----BEGIN PRIVATE KEY-----\n" +
                    "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAOgnDGWFegRt0WDL\n" +
                    "HfEJ3vH3kSV7ndvPvyb4Sp7xqQNekZxJWXhgNh5r3LcDdPCN0Tck+QcOsnz0DUlF\n" +
                    "NwdKOrWTLUmOrRzV3gEoVL2whztNvVxfJ21lfIiY9k3NPNib5T/gsG3RJt3XBXmK\n" +
                    "3oHx8Yu6NnY+GHiNwsyPiLQljOSnAgMBAAECgYAWP8/PVwiHriK3/R+Ef2avmAOA\n" +
                    "LSXG8FUonflA3HZPTVv1N45snAPzzHCd1aX6fA0GFPQM+hqfISC42fpZJ4MSvx8G\n" +
                    "s/li2h99YQX+shN+o+AKXnKdsqYTSarriTy9/CC6PZAMPC0bjNr7VlWVY2g2DOJO\n" +
                    "vmo8teZ4fGu+vAD50QJBAP7HGXIW5fLrBv+ymfuD/WdSEOhOoiagz4pdGE5j+Qwj\n" +
                    "6HoJnTMpAPlHJroPsjOPM2Bodg3fjBygzkWpqvZn3P8CQQDpRCmMtTz6vN7+Ot7d\n" +
                    "O58XquhnHWyYVLxJkQyRdk/QXj58cgBBAlEHDNsjQ6KAu98Xo99O337rhW08Xvfp\n" +
                    "vvBZAkA4YIpK6rI7jLJhxn24YD6krE49eZj7/z2tmmgUgJ7NhuychKAagApNHud8\n" +
                    "6JhAPIHb5YGqFDuG4jaCx8ai+9y1AkB8IJNjlsXeP0cCTd1uKF3eQEnvJQ82eFDB\n" +
                    "bPgdJ7INFTl3C0rrTQpFEChEOadtjYuHjuIznGZzecrJB1gxADPxAkEA+Kg9koba\n" +
                    "M49YTfSq0lEnDWUkOogwAA9a72NE+YsHvZ1FDR+0WJxORK8NYcnOUaB/B6l2aUAz\n" +
                    "luYutWoDw/04Fg==\n" +
                    "-----END PRIVATE KEY-----";
            System.out.println(pb);
            System.out.println(pr);

            String encryptStr = encryptByPublicKey("北京星立方", pb);
            System.out.println("加密结果："+encryptStr);
            String decryptStr = decryptByPrivateKey(encryptStr,pr);
            System.out.println("解密结果："+decryptStr);

            String signRes = sign("星视融通",pr);
            System.out.println("签名："+signRes);

            System.out.println("验签："+verify("星视融通",pb,signRes));

            String res = "3IkGRXy2WvlUvNa3knbbyVckwnGDCYk+olLYWJTSEonRW0V++Q3cHxI7Ise5Ixx+asFVUjYQzczSgTXhFhy4zjorrmuJf8DeBU9R2dopY0iue8R7XyUp+XFvQqeHJ0Qjv0Vkqp+LGNM6GTNde/EXC/fwUWljVLByPz4n1IiH+rE=";
            System.out.println(decryptByPrivateKey(res,pr));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
