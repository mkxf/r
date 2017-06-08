package com.ai.mampcore.util;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.ai.frame.logger.Logger;
import com.ai.frame.logger.LoggerFactory;
import com.ai.mampcore.exception.BasicBusiException;

public class EncryptionUtil {
    private EncryptionUtil() {
    }

    private static final String ALGORITHM = "DES";

    /**
     * Get Des Key
     */
    public static byte[] getKey() throws BasicBusiException, NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance(ALGORITHM);
        SecretKey deskey = keygen.generateKey();
        return deskey.getEncoded();
    }

    /**
     * Encrypt Messages
     */
    public static byte[] encode(byte[] input, byte[] key) throws BasicBusiException, GeneralSecurityException {
        SecretKey deskey = new javax.crypto.spec.SecretKeySpec(key, ALGORITHM);
        Cipher c1 = Cipher.getInstance(ALGORITHM);
        c1.init(Cipher.ENCRYPT_MODE, deskey);
        return c1.doFinal(input);
    }

    /**
     * Decrypt Messages
     */
    public static byte[] decode(byte[] input, byte[] key) throws BasicBusiException, GeneralSecurityException {
        SecretKey deskey = new javax.crypto.spec.SecretKeySpec(key, ALGORITHM);
        Cipher c1 = Cipher.getInstance(ALGORITHM);
        c1.init(Cipher.DECRYPT_MODE, deskey);
        return c1.doFinal(input);
    }

    /**
     * MD5
     */
    public static byte[] md5(byte[] input) throws BasicBusiException, GeneralSecurityException {
        java.security.MessageDigest alg = java.security.MessageDigest.getInstance("MD5"); // or "SHA-1"
        alg.update(input);
        return alg.digest();
    }

    /**
     * Convert byte[] to String
     */
    public static String byte2hex(byte[] b) {
        String hs = "";
        // String stmp = "";
        for (byte element : b) {
            String stmp = java.lang.Integer.toHexString(element & 0XFF);
            if (stmp.length() == 1) {
                hs = hs + "0" + stmp;
            } else {
                hs = hs + stmp;
            }
        }
        return hs.toUpperCase();
    }

    /**
     * Convert String to byte[]
     */
    public static byte[] hex2byte(String hex) throws IllegalArgumentException {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException();
        }
        char[] arr = hex.toCharArray();
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0, j = 0, l = hex.length(); i < l; i++, j++) {
            String swap = Character.toString(arr[i++]) + arr[i];
            int byteint = Integer.parseInt(swap, 16) & 0xFF;
            b[j] = Integer.valueOf(String.valueOf(byteint)).byteValue();
        }
        return b;
    }

    public static void main(String[] args) throws BasicBusiException, GeneralSecurityException {
        Logger logger = LoggerFactory.getApplicationLog(EncryptionUtil.class);
        String eS = byte2hex(encode("7aH^sdmG".getBytes(), "asiainfo".getBytes()));
        logger.info("加密后的wsyyt对应的字符串为：", eS);

        String s = new String(EncryptionUtil.decode(EncryptionUtil.hex2byte(eS), "asiainfo".getBytes()));
        logger.info("加密后的wsyyt对应的字符串为：",s);
    }
}
