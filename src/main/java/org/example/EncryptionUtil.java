package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class EncryptionUtil {

    private static final SecureRandom secureRandom = new SecureRandom();

    public static String encrypt(byte[] key, String data) throws Exception {
        SecretKey aesKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivParams);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        byte[] encryptedIVAndText = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, iv.length);
        System.arraycopy(encrypted, 0, encryptedIVAndText, iv.length, encrypted.length);
        return Base64.getEncoder().encodeToString(encryptedIVAndText);
    }

    public static String decrypt(byte[] key, String encryptedData) throws Exception {
        SecretKey aesKey = new SecretKeySpec(key, "AES");
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        byte[] iv = Arrays.copyOfRange(decoded, 0, 16);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        byte[] encrypted = Arrays.copyOfRange(decoded, 16, decoded.length);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivParams);
        byte[] original = cipher.doFinal(encrypted);
        return new String(original);
    }
}
