//package com.jaredlin.encrypt;
//
//import java.io.File;
//import java.security.Key;
//import java.util.Map;
//
//public class Main {
//
//    static String publicKey;
//    static String privateKey;
//
//    private static final  String BASE_FILE = "/sdcard/";
//
//
//    public static void main(String[] args) throws Exception {
//        genKey();
//        test();
//        testSign();
//    }
//
//    static void genKey(){
//        try {
//            Map<String, Key> keyMap = RSAUtils.genKeyPair();
//            publicKey = Base64Utils.encode(keyMap.get(RSAUtils.PUBLIC_KEY).getEncoded());
//            privateKey = Base64Utils.encode(keyMap.get(RSAUtils.PRIVATE_KEY).getEncoded());
//            System.err.println("公钥: \n\r" + publicKey);
//            System.err.println("私钥： \n\r" + privateKey);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        new File(BASE_FILE,"loggers");
//    }
//
//
//
//    static void test() throws Exception {
//        System.err.println("公钥加密——私钥解密");
//        String source = "这是一行没有任何意义的文字，你看完了等于没看，不是吗？";
//        System.out.println("\r加密前文字：\r\n" + source);
//        byte[] data = source.getBytes();
//        byte[] encodedData = RSAUtils.encryptByPublicKey(data, publicKey);
//        System.out.println("加密后文字：\r\n" + Base64Utils.urlsafeEncode(encodedData));
//        byte[] decodedData = RSAUtils.decryptByPrivateKey(encodedData, privateKey);
//        String target = new String(decodedData);
//        System.out.println("解密后文字: \r\n" + target);
//    }
//
//    static void testSign() throws Exception {
//        System.err.println("私钥签名——公钥验证签名");
//        String source = "这是一行测试RSA数字签名的无意义文字";
//        System.out.println("原文字：\r\n" + source);
//        byte[] data = source.getBytes();
//        String sign = RSAUtils.sign(data, privateKey);
//        System.err.println("签名:\r" + sign);
//        boolean status = RSAUtils.verify(data, publicKey, sign);
//        System.err.println("验证结果:\r" + status);
//    }
//}
