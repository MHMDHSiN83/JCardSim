package com.licel.jcardsim.samples;

import javacard.framework.*;
import javacard.security.*;

public class HKDFManagerApplet extends Applet {
    // Instruction byte identifiers for different operations
    private static final byte INS_EXTRACT = (byte) 0x10;
    private static final byte INS_EXPAND  = (byte) 0x20;
    private static final byte INS_ROTATE  = (byte) 0x30;
    private static final byte INS_SET_SALT = (byte) 0x40; // New instruction for setting salt

    // Length of the PRK (Pseudo-Random Key) which is 32 bytes for SHA-256
    private static final short PRK_LENGTH = 32; // SHA-256 length
    private static final short MAX_SALT_LENGTH = 64; // Maximum allowed salt length

    // Buffers to hold temporary data
    private byte[] prkBuffer;
    private byte[] saltBuffer; // Buffer for dynamic salt
    private short saltLength; // Current salt length

    // HMAC signature instance for SHA-256
    private Signature hmac;

    // HMAC key instances for salt and PRK
    private HMACKey saltKey;
    private HMACKey prkKey;

    // Constructor to initialize the applet
    private HKDFManagerApplet() {
        // Initialize buffers
        prkBuffer = new byte[PRK_LENGTH];
        saltBuffer = new byte[MAX_SALT_LENGTH];
        saltLength = 0; // Initially no salt

        // Initialize HMAC for SHA-256 hashing
        hmac = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);

        // Initialize keys for HMAC operations
        saltKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
        prkKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);

        // Register the applet
        register();
    }

    // Install method to create an instance of the applet
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new HKDFManagerApplet();
    }

    // Main method to process APDU commands
    public void process(APDU apdu) {
        // Check if the applet is selected
        if (selectingApplet()) return;

        // Get the APDU buffer
        byte[] buffer = apdu.getBuffer();

        // Get the instruction byte from the APDU command
        byte ins = buffer[ISO7816.OFFSET_INS];

        // Switch between the instructions
        switch (ins) {
            case INS_EXTRACT:
                hkdfExtract(apdu);
                break;
            case INS_EXPAND:
                hkdfExpand(apdu);
                break;
            case INS_ROTATE:
                hkdfRotate(apdu);
                break;
            case INS_SET_SALT:
                setSalt(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // New method to set dynamic salt
    private void setSalt(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        
        // Get the length of the incoming salt data
        short saltLen = apdu.setIncomingAndReceive();
        
        // Check if the salt length is valid
        if (saltLen < 1 || saltLen > MAX_SALT_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        // Copy the salt into the buffer
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, saltBuffer, (short) 0, saltLen);
        saltLength = saltLen;
        
        // Optional: Send success status
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    // Modified hkdfExtract to use dynamic salt
    private void hkdfExtract(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short ikmLen = apdu.setIncomingAndReceive();

        if (ikmLen < 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Check if salt has been set
        if (saltLength == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Set the dynamic salt for the HMAC operation
        saltKey.setKey(saltBuffer, (short) 0, saltLength);
        hmac.init(saltKey, Signature.MODE_SIGN);

        short prkLen = hmac.sign(buffer, ISO7816.OFFSET_CDATA, ikmLen, prkBuffer, (short) 0);
        Util.arrayCopyNonAtomic(prkBuffer, (short) 0, buffer, (short) 0, prkLen);
        apdu.setOutgoingAndSend((short) 0, prkLen);
    }

    // Method for the HKDF expand operation (to expand PRK into output key material (OKM))
    private void hkdfExpand(APDU apdu) {
        // Get the APDU buffer.
        byte[] buffer = apdu.getBuffer();
    
        // Determine desired output length from P2. Default to 16 if 0.
        byte L = buffer[ISO7816.OFFSET_P2]; // P2 is at offset 3
        if (L == 0) {
            L = 16;
        }

        // Receive the "info" parameter from the incoming data.
        short infoLen = apdu.setIncomingAndReceive();
        byte[] info = new byte[infoLen];
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, info, (short) 0, infoLen);
    
        // For SHA-256, the hash output length is 32 bytes.
        short hashLen = PRK_LENGTH; // 32 bytes
        // Calculate the number of iterations: n = ceil(L/hashLen)
        short n = (short) ((L + hashLen - 1) / hashLen);
        if (n > 255) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA); // Too much output requested
        }
    
        // Prepare a buffer to hold the final output.
        byte[] okm = new byte[L];
        short bytesCopied = 0;
    
        // Temporary buffers:
        byte[] t_i = new byte[hashLen];     // Current block T(i)
        byte[] prevT = new byte[hashLen];   // Previous block T(i-1); T(0) is empty.
        // Maximum input size: previous block (hashLen) + info + 1 counter byte.
        byte[] blockInput = new byte[(short)(hashLen + infoLen + 1)];
    
        // Set the PRK as the key for the HMAC operation.
        prkKey.setKey(prkBuffer, (short) 0, (short) prkBuffer.length);
        hmac.init(prkKey, Signature.MODE_SIGN);
    
        // Iterate from i = 1 to n to generate T(1) ... T(n)
        for (short i = 1; i <= n; i++) {
            short offset = 0;
            // For i > 1, start with T(i-1)
            if (i > 1) {
                Util.arrayCopyNonAtomic(prevT, (short) 0, blockInput, (short) 0, hashLen);
                offset = hashLen;
            }
            // Append the info parameter.
            Util.arrayCopyNonAtomic(info, (short) 0, blockInput, offset, infoLen);
            offset += infoLen;
            // Append the counter i (as a single byte).
            blockInput[offset] = (byte) i;
            short blockInputLen = (short)(offset + 1);
    
            // Compute T(i) = HMAC(PRK, (T(i-1) || info || i))
            hmac.sign(blockInput, (short) 0, blockInputLen, t_i, (short) 0);
    
            // Copy T(i) (or part of it) into the OKM buffer.
            short copyLen = (short)((L - bytesCopied) < hashLen ? (L - bytesCopied) : hashLen);
            Util.arrayCopyNonAtomic(t_i, (short) 0, okm, bytesCopied, copyLen);
            bytesCopied += copyLen;
    
            // Save t_i for the next iteration.
            Util.arrayCopyNonAtomic(t_i, (short) 0, prevT, (short) 0, hashLen);
        }
    
        // Copy the OKM into the APDU buffer and send it back to the host.
        Util.arrayCopyNonAtomic(okm, (short) 0, buffer, (short) 0, (short) okm.length);
        apdu.setOutgoingAndSend((short) 0, (short) okm.length);
    }
    

    // Method for the HKDF rotate operation (to "rotate" the PRK for further use)
    private void hkdfRotate(APDU apdu) {
        // Get the buffer from the APDU
        byte[] buffer = apdu.getBuffer();

        // Define a label for the rotate operation (could be used for key diversification)
        byte[] label = { 'r', 'o', 't', 'a', 't', 'e' };

        // Get the length of the label
        short labelLen = (short) label.length;

        // Calculate the total input length (label + counter byte)
        short inputLen = (short)(labelLen + 1);

        // Create an input buffer with the label + counter byte
        byte[] input = new byte[inputLen];

        // Copy the label into the input buffer
        Util.arrayCopyNonAtomic(label, (short) 0, input, (short) 0, labelLen);

        // Append the counter byte (1) at the end of the label
        input[(short)(inputLen - 1)] = 1;

        // Set the PRK key for the HMAC operation
        prkKey.setKey(prkBuffer, (short) 0, (short) prkBuffer.length);

        // Initialize HMAC with the PRK key in signing mode
        hmac.init(prkKey, Signature.MODE_SIGN);

        // Perform HMAC signing to "rotate" the PRK and generate new key material
        hmac.sign(input, (short) 0, inputLen, prkBuffer, (short) 0);

        // Send the rotated PRK back to the client
        apdu.setOutgoingAndSend((short) 0, (short) 32);
    }


    // this is for test
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
