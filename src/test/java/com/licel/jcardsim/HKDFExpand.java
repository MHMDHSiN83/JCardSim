package com.licel.jcardsim;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.nio.ByteBuffer;

public class HKDFExpand {

    public static byte[] hkdfExpand(byte[] prk, byte[] info, int outputLength) 
        throws NoSuchAlgorithmException, InvalidKeyException {
        

        if (prk == null || prk.length == 0) {
            throw new IllegalArgumentException("PRK cannot be null or empty");
        }
        if (outputLength < 1 || outputLength > 255 * 32) {
            throw new IllegalArgumentException("Invalid output length");
        }


        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(prk, "HmacSHA256"));


        int hashLength = 32;
        int n = (int) Math.ceil((double) outputLength / hashLength);


        ByteBuffer okm = ByteBuffer.allocate(outputLength);


        byte[] T = new byte[0];


        for (int i = 1; i <= n; i++) {

            ByteBuffer input = ByteBuffer.allocate(T.length + info.length + 1);
            input.put(T);
            input.put(info);
            input.put((byte) i);


            hmac.reset();
            T = hmac.doFinal(input.array());


            int bytesToCopy = Math.min(hashLength, outputLength - okm.position());
            okm.put(T, 0, bytesToCopy);
        }


        return okm.array();
    }


    public static void main(String[] args) throws Exception {

        byte[] prk = hexStringToByteArray("616c16be56cef44e8f6f36aae880ec42338c854c9c4188a238b3233a8a1c0b7d");
        byte[] info = "aes-key".getBytes();
        int L = 16;

        byte[] okm = hkdfExpand(prk, info, L);
        System.out.println("OKM: " + bytesToHex(okm));
    }


    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}