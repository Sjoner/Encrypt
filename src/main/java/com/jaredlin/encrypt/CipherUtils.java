package com.jaredlin.encrypt;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by linmq on 2017/5/12.
 */

public class CipherUtils {

    public static class TripleDES{
        /**
         * 3DES转变
         * <p>法算法名称/加密模式/填充方式</p>
         * <p>加密模式有：电子密码本模式ECB、加密块链模式CBC、加密反馈模式CFB、输出反馈模式OFB</p>
         * <p>填充方式有：NoPadding、ZerosPadding、PKCS5Padding</p>
         */
        private static String TripleDES_Transformation = "DESede/ECB/NoPadding";
        private static final String TripleDES_Algorithm = "DESede";

        public static byte[] encrypt(byte[] data, byte[] key) {
            return CipherUtils.encrypt(data, key, TripleDES_Algorithm, TripleDES_Transformation);
        }

        public static byte[] decrypt(byte[] data, byte[] key) {
            return CipherUtils.decrypt(data, key, TripleDES_Algorithm, TripleDES_Transformation);
        }
    }

    public static class DES{
        /**
         * DES转变
         * <p>法算法名称/加密模式/填充方式</p>
         * <p>加密模式有：电子密码本模式ECB、加密块链模式CBC、加密反馈模式CFB、输出反馈模式OFB</p>
         * <p>填充方式有：NoPadding、ZerosPadding、PKCS5Padding</p>
         */
        private static String DES_TRANSFORMATION  = "DES/ECB/NoPadding";
        private static final String DES_ALGORITHM = "DES";

        public static byte[] encrypt(byte[] data, byte[] key) {
            return CipherUtils.encrypt(data, key, DES_ALGORITHM, DES_TRANSFORMATION);
        }

        public static byte[] decrypt(byte[] data, byte[] key) {
            return CipherUtils.decrypt(data, key, DES_ALGORITHM, DES_TRANSFORMATION);
        }
    }

    public static class AES{
        private static final String AES_TRANSFORMATION = "AES/ECB/NoPadding";
        private static final String AES_ALGORITHM = "AES";
        public static byte[] encrypt(byte[] data, byte[] key) {
            return CipherUtils.encrypt(data, key, AES_ALGORITHM, AES_TRANSFORMATION);
        }

        public static byte[] decrypt(byte[] data, byte[] key) {
            return CipherUtils.decrypt(data, key, AES_ALGORITHM, AES_TRANSFORMATION);
        }

    }

    public static byte[] encrypt(byte[] data, byte[] key, String algorithm, String transformation){
        return core(data, key, algorithm, transformation, Cipher.ENCRYPT_MODE);
    }

    public static byte[] decrypt(byte[] data, byte[] key, String algorithm, String transformation) {
        return core(data, key, algorithm, transformation, Cipher.DECRYPT_MODE);
    }

    private static byte[] core(byte[] data, byte[] key, String algorithm, String transformation,
                              int mode) {
        if (data == null || data.length == 0 || key == null || key.length == 0) {
            return null;
        }
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
            Cipher cipher = Cipher.getInstance(transformation);
            SecureRandom random = new SecureRandom();
            cipher.init(mode, keySpec, random);
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
