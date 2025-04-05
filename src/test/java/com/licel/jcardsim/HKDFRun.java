package com.licel.jcardsim;

import com.licel.jcardsim.samples.HKDFManagerApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import javacard.framework.AID;


// To check the correct functioning of the JavaCard
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public class HKDFRun {
    public static void main(String[] args) {
        // Initialize the simulator
        CardSimulator simulator = new CardSimulator();
        
        // Install and select applet
        byte[] appletAIDBytes = {(byte)0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, 0x01};
        AID appletAID = new AID(appletAIDBytes, (short)0, (byte)appletAIDBytes.length);
        simulator.installApplet(appletAID, HKDFManagerApplet.class);
        simulator.selectApplet(appletAID);

        // ========== TEST SETUP ==========
        byte[] dynamicSalt = {
            (byte)0xDA, (byte)0xAC, 0x3E, 0x10, 0x55, (byte)0xB5, (byte)0xF1, 0x3E,
            0x53, (byte)0xE4, 0x70, (byte)0xA8, 0x77, 0x79, (byte)0x8E, 0x0A,
            (byte)0x89, (byte)0xAE, (byte)0x96, 0x5F, 0x19, 0x5D, 0x53, 0x62,
            0x58, (byte)0x84, 0x2C, 0x09, (byte)0xAD, 0x6E, 0x20, (byte)0xD4
        };
        
        byte[] ikm = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        };
        
        byte[] info = "aes-key".getBytes();
        short outputLen = 32;

        System.out.println("=== TEST PARAMETERS ===");
        System.out.println("Salt:      " + bytesToHex(dynamicSalt));
        System.out.println("IKM:       " + bytesToHex(ikm));
        System.out.println("Info:      " + bytesToHex(info));
        System.out.println("OutputLen: " + outputLen + "\n");

        // ========== JAVA CARD IMPLEMENTATION ==========
        System.out.println("=== JAVA CARD HKDF ===");
        
        // Set salt
        CommandAPDU setSaltAPDU = new CommandAPDU(0x00, 0x40, 0x00, 0x00, dynamicSalt);
        ResponseAPDU setSaltResponse = simulator.transmitCommand(setSaltAPDU);
        System.out.println("Set Salt Status: " + Integer.toHexString(setSaltResponse.getSW()));

        // Extract
        CommandAPDU extractAPDU = new CommandAPDU(0x00, 0x10, 0x00, 0x00, ikm);
        ResponseAPDU extractResponse = simulator.transmitCommand(extractAPDU);
        byte[] jcPRK = extractResponse.getData();
        System.out.println("JC PRK:          " + bytesToHex(jcPRK));

        // Expand
        CommandAPDU expandAPDU = new CommandAPDU(0x00, 0x20, 0x00, (byte)outputLen, info);
        ResponseAPDU expandResponse = simulator.transmitCommand(expandAPDU);
        byte[] jcOKM = expandResponse.getData();
        System.out.println("JC OKM:          " + bytesToHex(jcOKM) + "\n");

        // ========== BOUNCY CASTLE IMPLEMENTATION ==========
        System.out.println("=== BOUNCY CASTLE HKDF ===");
        
        // Extract
        byte[] bcPRK = hkdfExtract(ikm, dynamicSalt);
        System.out.println("BC PRK:          " + bytesToHex(bcPRK));
        
        // Expand (with verbose output)
        System.out.println("\nBC Expand Steps:");
        byte[] bcOKM = hkdfExpandVerbose(bcPRK, info, outputLen);
        System.out.println("\nBC OKM:          " + bytesToHex(bcOKM) + "\n");

        // ========== COMPARISON ==========
        System.out.println("=== COMPARISON ===");
        System.out.println("PRK Match:       " + Arrays.equals(jcPRK, bcPRK));
        System.out.println("OKM Match:       " + Arrays.equals(jcOKM, bcOKM));
    }

    // Verbose HKDF-Expand that prints each iteration
    private static byte[] hkdfExpandVerbose(byte[] prk, byte[] info, int length) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(prk, "HmacSHA256"));

            byte[] result = new byte[length];
            byte[] t = new byte[0];
            int offset = 0;
            byte i = 1;

            while (offset < length) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                bos.write(t);
                bos.write(info);
                bos.write(i);
                
                byte[] input = bos.toByteArray();
                System.out.println("T" + i + " Input:  " + bytesToHex(input));
                
                t = hmac.doFinal(input);
                System.out.println("T" + i + " Output: " + bytesToHex(t));
                
                int copyLength = Math.min(t.length, length - offset);
                System.arraycopy(t, 0, result, offset, copyLength);
                offset += copyLength;
                i++;
            }
            return result;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] hkdfExtract(byte[] ikm, byte[] salt) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(salt, "HmacSHA256"));
            return hmac.doFinal(ikm);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(prk, "HmacSHA256"));

            byte[] result = new byte[length];
            byte[] t = new byte[0];
            int offset = 0;
            byte i = 1;

            while (offset < length) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                bos.write(t);
                bos.write(info);
                bos.write(i);
                t = hmac.doFinal(bos.toByteArray());
                
                int copyLength = Math.min(t.length, length - offset);
                System.arraycopy(t, 0, result, offset, copyLength);
                offset += copyLength;
                i++;
            }
            return result;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}