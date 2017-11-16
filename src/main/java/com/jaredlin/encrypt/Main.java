//package com.jaredlin.encrypt;
//
//import java.security.Key;
//import java.util.Map;
//import java.util.concurrent.CountDownLatch;
//
//public class Main {
//
//    static String publicKey;
//    static String privateKey;
//
//    public static void main(String[] args) throws Exception {
//        System.out.println("\n=======================");
//        genKey();
//        System.out.println("\n=======================");
//        test();
////        System.out.println("\n=======================");
////        testSign();
//    }
//
//    static void genKey(){
//        try {
//            Map<String, Key> keyMap = RSAUtils.genKeyPair(1024);
//            publicKey = Base64Utils.encode(keyMap.get(RSAUtils.PUBLIC_KEY).getEncoded());
//            privateKey = Base64Utils.encode(keyMap.get(RSAUtils.PRIVATE_KEY).getEncoded());
//
//            System.out.println("公钥: \n\r" + publicKey);
//            System.out.println("私钥： \n\r" + privateKey);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//
//
//
//    static void test() throws Exception {
//        System.out.println("公钥加密——私钥解密");
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
//        System.out.println("私钥签名——公钥验证签名");
//        String source = "这是一行测试RSA数字签名的无意义文字";
//        System.out.println("原文字：\r\n" + source);
//        byte[] data = source.getBytes();
//        String sign = RSAUtils.sign(data, privateKey,RSAUtils.SIGNATURE_ALGORITHM);
//        System.out.println("签名:\r" + sign);
//        boolean status = RSAUtils.verify(data, publicKey, sign,RSAUtils.SIGNATURE_ALGORITHM);
//        System.out.println("验证结果:\r" + status);
//    }
//}
