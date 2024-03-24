package org.example;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class Main {

    private enum Command {
        init, put, get
    }

    private static Map<String, String> passwordStore = new HashMap<>();

    public static void main(String[] args) throws Exception {

        String command = args[0];


        String masterPass;
        String url;
        String pass;
        switch (Command.valueOf(command)) {
            case init:
                String value = args[1];
                initMasterPassword(value.toCharArray());
                break;
            case put:
                masterPass = args[1];
                url  = args[2];
                pass = args[3];
                putNewPas(masterPass.toCharArray(), url, pass);
                break;
            case get:
                masterPass = args[1];
                url = args[2];
                getPass(masterPass.toCharArray(), url);
                break;
        }
    }

    public static void initMasterPassword(char[] masterPassword) throws Exception {
        initializePasswordStore();

        byte[] salt = generateSalt();
        byte[] key = getEncryptionKey(masterPassword, salt);

        encryptAndStore(key, masterPassword, salt);
        System.out.println("Vault initialized successfully!");
    }

    public static void getPass(char[] masterPass, String url) throws Exception {
        String[] saltAndHmac = readSaltAndHmac();
        String saltEncoded = saltAndHmac[0];
        byte[] salt = decode(saltEncoded);
        String hmacOld = saltAndHmac[1];

        String encryptedData = readData();
        byte[] hmacKey = getHmacKey(masterPass, salt);
        String hmacNew = calculateHMAC(encryptedData, hmacKey);
        boolean isSuccessful = hmacNew.equals(hmacOld);

        if (!isSuccessful) {
            System.out.println("ERR -> Password not correct or integrity compromised!");
            return;
        }

        byte[] encryptionKey = getEncryptionKey(masterPass, salt);
        String rawData = EncryptionUtil.decrypt(encryptionKey, encryptedData);
        passwordStore = parseMapFromString(rawData);
        String pass = passwordStore.get(url);
        System.out.println("Password: " + pass);
    }


    public static void putNewPas(char[] masterPass, String url, String pass) throws Exception {
        String[] saltAndHmac = readSaltAndHmac();
        String saltEncoded = saltAndHmac[0];
        byte[] salt = decode(saltEncoded);
        String hmacOld = saltAndHmac[1];

        String encryptedData = readData();
        byte[] hmacKey = getHmacKey(masterPass, salt);
        String hmacNew = calculateHMAC(encryptedData, hmacKey);
        boolean isSuccessful = hmacNew.equals(hmacOld);

        if (!isSuccessful) {
            System.out.println("ERR -> Password not correct or integrity compromised!");
            return;
        }

        byte[] encryptionKey = getEncryptionKey(masterPass, salt);
        String rawData = EncryptionUtil.decrypt(encryptionKey, encryptedData);
        passwordStore = parseMapFromString(rawData);
        passwordStore.put(url, pass);

        byte[] newSalt = generateSalt();
        byte[] newEncryptionKey = getEncryptionKey(masterPass, newSalt);
        encryptAndStore(newEncryptionKey, masterPass, newSalt);
        System.out.println("New key value pair successfully stored!");
    }

    public static void encryptAndStore(byte[] encryptionKey, char[] masterPassword, byte[] salt) throws Exception {
        String encryptedData = EncryptionUtil.encrypt(encryptionKey, serializeIntoString(passwordStore));
        storeData(encryptedData);

        byte[] hmacKey = getHmacKey(masterPassword, salt);
        String hmac = calculateHMAC(encryptedData, hmacKey);

        String saltString = Base64.getEncoder().encodeToString(salt);
        storeSaltAndHmac(saltString, hmac);
    }

    public static byte[] decode(String s) {
        return Base64.getDecoder().decode(s);
    }

    public static String serializeIntoString(Object o) {
        return o.toString();
    }

    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }
    public static byte[] getEncryptionKey(char[] masterPassword, byte[] salt) {
        return hashPassword(masterPassword, salt, 65536);
    }

    public static byte[] getHmacKey(char[] masterPassword, byte[] salt) {
        return hashPassword(masterPassword, salt, 65535);
    }

    public static void storeData(String data) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("data.txt"))) {
            oos.writeObject(data);
        } catch (IOException e) {
            System.out.println("Error storing the salt: " + e.getMessage());
        }
    }

    public static String readData() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data.txt"))) {
            return (String) ois.readObject();

        } catch (Exception e) {
            System.out.println("Error reading the salt and HMAC: " + e.getMessage());
        }
        return null;
    }

    public static byte[] hashPassword(char[] password, byte[] salt, int iterations) {
        try {
            int keyLength = 256;
            KeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Error while hashing a password: " + e.getMessage(), e);
        }
    }

    public static void storeSaltAndHmac(String salt, String hmac) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("metadata.txt"))) {
            oos.writeObject(salt);
            oos.writeObject(hmac);
        } catch (IOException e) {
            System.out.println("Error storing the salt: " + e.getMessage());
        }
    }

    public static String[] readSaltAndHmac() {
        String[] saltAndHmac = new String[2]; // Array to hold the salt and HMAC

        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("metadata.txt"))) {
            saltAndHmac[0] = (String) ois.readObject(); // Read salt
            saltAndHmac[1] = (String) ois.readObject(); // Read HMAC

        } catch (Exception e) {
            System.out.println("Error reading the salt and HMAC: " + e.getMessage());
        }
        return saltAndHmac;
    }

    public static void initializePasswordStore() {
        passwordStore.clear();
        passwordStore.put(UUID.randomUUID().toString(), UUID.randomUUID().toString());
    }

    public static String calculateHMAC(String data, byte[] hmacKey) {
        try {
            String algorithm = "HmacSHA256";
            SecretKeySpec keySpec = new SecretKeySpec(hmacKey, algorithm);

            Mac mac = Mac.getInstance(algorithm);
            mac.init(keySpec);

            byte[] rawHmac = mac.doFinal(data.getBytes());

            return Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("Error while calculating HMAC", e);
        }
    }

    public static Map<String, String> parseMapFromString(String mapAsString) {
        mapAsString = mapAsString.substring(1, mapAsString.length() - 1);
        Map<String, String> map = new HashMap<>();
        String[] pairs = mapAsString.split(", ");

        for (String pair : pairs) {
            String[] keyValue = pair.split("=");
            map.put(keyValue[0], keyValue.length > 1 ? keyValue[1] : "");
        }

        return map;
    }
}