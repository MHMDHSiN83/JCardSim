package com.licel.jcardsim;

import com.licel.jcardsim.samples.HKDFManagerApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import javacard.framework.AID;
import junit.framework.TestCase;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.digests.SHA256Digest;
import java.util.Arrays;

public class HKDFRun {
    // Define the same static salt as used in your applet.
    private static final byte[] STATIC_SALT = new byte[]{
        (byte)0xDA, (byte)0xAC, 0x3E, 0x10, 0x55, (byte)0xB5, (byte)0xF1, 0x3E,
        0x53, (byte)0xE4, 0x70, (byte)0xA8, 0x77, 0x79, (byte)0x8E, 0x0A,
        (byte)0x89, (byte)0xAE, (byte)0x96, 0x5F, 0x19, 0x5D, 0x53, 0x62,
        0x58, (byte)0x84, 0x2C, 0x09, (byte)0xAD, 0x6E, 0x20, (byte)0xD4
    };

    public static void main(String[] args) {
        // Initialize the simulator from jCardSim.
        CardSimulator simulator = new CardSimulator();

        // Define an AID for the HKDFManagementApplet.
        byte[] appletAIDBytes = new byte[]{
            (byte)0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, 0x01
        };
        AID appletAID = new AID(appletAIDBytes, (short) 0, (byte) appletAIDBytes.length);

        // Install and select the HKDFManagementApplet.
        simulator.installApplet(appletAID, HKDFManagerApplet.class);
        simulator.selectApplet(appletAID);

        // ---- Test HKDF-Extract ----
        byte[] ikm = new byte[]{
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C,
            0x0D, 0x0E, 0x0F, 0x10
        };
        CommandAPDU extractAPDU = new CommandAPDU(0x00, 0x10, 0x00, 0x00, ikm);
        ResponseAPDU extractResponse = simulator.transmitCommand(extractAPDU);
        byte[] prkFromApplet = extractResponse.getData();
        System.out.println("JavaCard PRK: " + bytesToHex(prkFromApplet));

        // ---- Test HKDF-Expand ----
        byte[] info = "aes-key".getBytes();
        CommandAPDU expandAPDU = new CommandAPDU(0x00, 0x20, 0x00, 0x00, info);
        ResponseAPDU expandResponse = simulator.transmitCommand(expandAPDU);
        byte[] derivedKeyFromApplet = expandResponse.getData();
        System.out.println("JavaCard Derived Key: " + bytesToHex(derivedKeyFromApplet));

        // ---- Compare with Bouncy Castle Implementation ----
        // Use the same STATIC_SALT for extraction.
        byte[] prkBC = hkdfExtract(ikm, STATIC_SALT);
        byte[] derivedKeyBC = hkdfExpand(prkBC, info, 16);

        System.out.println("Bouncy Castle PRK: " + bytesToHex(prkBC));
        System.out.println("PRK Match: " + Arrays.equals(prkFromApplet, prkBC));
    }

    // HKDF Extract using Bouncy Castle
    private static byte[] hkdfExtract(byte[] ikm, byte[] salt) {
        HMac hmac = new HMac(new SHA256Digest());
        hmac.init(new KeyParameter(salt));
        byte[] prk = new byte[32]; // PRK length for SHA-256
        hmac.update(ikm, 0, ikm.length);
        hmac.doFinal(prk, 0);
        return prk;
    }

    // HKDF Expand using Bouncy Castle
    private static byte[] hkdfExpand(byte[] prk, byte[] info, int outputLength) {
        // Prepare a buffer to hold the output key material (OKM)
        byte[] okm = new byte[outputLength];
        
        // Initialize HMAC with PRK and SHA-256
        HMac hmac = new HMac(new SHA256Digest());
        hmac.init(new KeyParameter(prk));
        
        byte[] previousBlock = new byte[hmac.getMacSize()];
        byte counter = 1;
        int offset = 0;
        
        // Generate the key in blocks
        while (offset < outputLength) {
            // Create a buffer for the current block to be derived
            byte[] currentBlock = new byte[previousBlock.length + info.length + 1];
            
            // Copy the previous block
            System.arraycopy(previousBlock, 0, currentBlock, 0, previousBlock.length);
            
            // Append the info
            System.arraycopy(info, 0, currentBlock, previousBlock.length, info.length);
            
            // Append the counter byte
            currentBlock[currentBlock.length - 1] = counter;
            
            // Perform HMAC operation on the current block to generate the next block of OKM
            hmac.update(currentBlock, 0, currentBlock.length);
            hmac.doFinal(previousBlock, 0);
            
            // Copy the result into the OKM buffer
            int remaining = outputLength - offset;
            int blockSize = Math.min(remaining, previousBlock.length);
            System.arraycopy(previousBlock, 0, okm, offset, blockSize);
            offset += blockSize;
            
            // Increment the counter for the next block
            counter++;
        }
        
        return okm;
    }
    
    
    // Utility method to convert a byte array to a hex string.
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
