/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sakadream.security;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

/**
 * Encrypt / Decrypt Utility
 *
 * @author Phan Ba Hai
 */
public class Security {

    private static final String KEY1 = "kZ,.7wZ$2T=<vgx9";
    private static final String KEY2 = ",6Z4Z.Fxm%L4ruPy";
    private static Key aesKey;
    private static Cipher cipher;
    private static final IvParameterSpec iv = new IvParameterSpec(KEY2.getBytes());

    private static void init() throws NoSuchAlgorithmException, NoSuchPaddingException {
        aesKey = new SecretKeySpec(KEY1.getBytes(), "AES");
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    /**
     * Encrypt plain text to encrypted text
     *
     * @param plainText The plain text
     * @return String
     * @throws java.security.NoSuchAlgorithmException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.io.UnsupportedEncodingException
     */
    public static String encrypt(String plainText)
            throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidAlgorithmParameterException,
            UnsupportedEncodingException {
        init();
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.encodeBase64String(encryptedBytes);
    }

    /**
     * Decrypt encrypted text to plain text
     *
     * @param encryptedText The encrypted text
     * @return String
     * @throws java.security.InvalidKeyException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.security.NoSuchAlgorithmException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.io.UnsupportedEncodingException
     */
    public static String decrypt(String encryptedText) throws
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchPaddingException,
            UnsupportedEncodingException {
        init();
        cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
        byte[] decryptedBytes = cipher.doFinal(Base64.decodeBase64(encryptedText));
        return new String(decryptedBytes, "UTF-8");
    }

    /**
     *
     * @param encryptedFile The Encrypted File
     * @return String
     * @throws Exception
     */
    public static String decrypt(File encryptedFile) throws Exception {
        FileReader fr = new FileReader(encryptedFile);
        BufferedReader br = new BufferedReader(fr);
        String text = "";
        String line = br.readLine();
        while (line != null) {
            text += line;
            line = br.readLine();
        }
        return decrypt(text);
    }
}
