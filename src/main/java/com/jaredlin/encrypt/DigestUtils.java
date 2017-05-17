package com.jaredlin.encrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by linmq on 2017/5/12.
 * 摘要工具类
 */
public class DigestUtils {

    public static final String ALGORITHM_SHA1 = "SHA1";
    public static final String ALGORITHM_MD5 = "MD5";

    public static byte[] digestMD5(byte[] data) {
        return digest(data, ALGORITHM_MD5);
    }

    public static byte[] digestMD5(byte[] data, byte[] salt) {
        if (data == null || salt == null) {
            return null;
        }
        byte[] dataSalt = new byte[data.length + salt.length];
        System.arraycopy(data, 0, dataSalt, 0, data.length);
        System.arraycopy(salt, 0, dataSalt, data.length, salt.length);
        return digestMD5(dataSalt);
    }

    public static byte[] digestSHA1(byte[] data) {
        return digest(data, ALGORITHM_SHA1);
    }

    public static byte[] digest(byte[] data, String algorithm) {
        if (data == null || data.length <= 0) {
            return null;
        }
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            md.update(data);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] digestFile(File file, String algorithm) {
        if (file == null) return null;
        FileInputStream fis = null;
        DigestInputStream digestInputStream;
        try {
            fis = new FileInputStream(file);
            MessageDigest md = MessageDigest.getInstance(algorithm);
            digestInputStream = new DigestInputStream(fis, md);
            byte[] buffer = new byte[256 * 1024];
            while (true) {
                if (!(digestInputStream.read(buffer) > 0)) break;
            }
            md = digestInputStream.getMessageDigest();
            return md.digest();
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            return null;
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
