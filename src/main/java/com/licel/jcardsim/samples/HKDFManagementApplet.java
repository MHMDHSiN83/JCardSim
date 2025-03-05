package com.licel.jcardsim.samples;


import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class HKDFManagementApplet extends Applet {
    // APDU instruction constants
    private static final byte INS_EXTRACT = (byte) 0x10;
    private static final byte INS_EXPAND  = (byte) 0x20;
    private static final byte INS_ROTATE  = (byte) 0x30;

    // A static salt (32 bytes) used in the HKDF-Extract step.
    private static final byte[] STATIC_SALT = {
        (byte)0xDA, (byte)0xAC, 0x3E, 0x10, 0x55, (byte)0xB5, (byte)0xF1, 0x3E,
        0x53, (byte)0xE4, 0x70, (byte)0xA8, 0x77, 0x79, (byte)0x8E, 0x0A,
        (byte)0x89, (byte)0xAE, (byte)0x96, 0x5F, 0x19, 0x5D, 0x53, 0x62,
        0x58, (byte)0x84, 0x2C, 0x09, (byte)0xAD, 0x6E, 0x20, (byte)0xD4
    };

    // Storage for the pseudorandom key (PRK) computed in the extract step (32 bytes for SHA-256)
    private byte[] prkBuffer;

    // HMAC instance using HMAC-SHA256 (Java Card API)
    private Signature hmac;

    private HKDFManagementApplet() {
        prkBuffer = new byte[32];  // Allocate space for PRK.
        hmac = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new HKDFManagementApplet();
    }

    public void process(APDU apdu) {
        if (selectingApplet())
            return;
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

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
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * HKDF-Extract: Computes PRK = HMAC(STATIC_SALT, IKM)
     * Expects the input keying material (IKM) in the APDU data.
     * Returns the 32-byte PRK to the caller.
     */
    private void hkdfExtract(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // Receive the IKM from the APDU
        short ikmLen = apdu.setIncomingAndReceive();

        // Set up an HMAC key with the STATIC_SALT.
        HMACKey saltKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC,
                KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
        saltKey.setKey(STATIC_SALT, (short) 0, (short) STATIC_SALT.length);
        hmac.init(saltKey, Signature.MODE_SIGN);

        // Compute PRK = HMAC(STATIC_SALT, IKM)
        short prkLen = hmac.sign(buffer, ISO7816.OFFSET_CDATA, ikmLen, prkBuffer, (short) 0);
        // Return the PRK to the host
        Util.arrayCopyNonAtomic(prkBuffer, (short) 0, buffer, (short) 0, prkLen);
        apdu.setOutgoingAndSend((short) 0, prkLen);
    }

    /**
     * HKDF-Expand: Computes T(1) = HMAC(PRK, info || 0x01) and returns the first 16 bytes.
     * Expects the optional "info" value in the APDU data.
     */
    private void hkdfExpand(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short infoLen = apdu.setIncomingAndReceive();
        
        // Prepare input: info || 0x01
        short inputLen = (short)(infoLen + 1);
        byte[] input = new byte[inputLen];
        if (infoLen > 0) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, input, (short) 0, infoLen);
        }
        input[(short)(inputLen - 1)] = 1;  // Append counter value 0x01

        // Use the stored PRK as the HMAC key.
        HMACKey prkKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC,
                KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
        prkKey.setKey(prkBuffer, (short) 0, (short) prkBuffer.length);
        hmac.init(prkKey, Signature.MODE_SIGN);

        // Compute HMAC(PRK, info || 0x01)
        byte[] okmFull = new byte[32]; // Full HMAC output (SHA-256 gives 32 bytes)
        hmac.sign(input, (short) 0, inputLen, okmFull, (short) 0);

        // Return the first 16 bytes as the derived key material.
        Util.arrayCopyNonAtomic(okmFull, (short) 0, buffer, (short) 0, (short) 16);
        apdu.setOutgoingAndSend((short) 0, (short) 16);
    }

    /**
     * Key Rotation: Updates the PRK using a fixed label ("rotate").
     * Computes new PRK = HMAC(PRK, "rotate" || 0x01) and stores it.
     * Returns the new 32-byte PRK.
     */
    private void hkdfRotate(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // Fixed label "rotate"
        byte[] label = { 'r', 'o', 't', 'a', 't', 'e' };
        short labelLen = (short) label.length;

        // Prepare input: label || 0x01
        short inputLen = (short)(labelLen + 1);
        byte[] input = new byte[inputLen];
        Util.arrayCopyNonAtomic(label, (short) 0, input, (short) 0, labelLen);
        input[(short)(inputLen - 1)] = 1;

        // Use the current PRK as HMAC key.
        HMACKey prkKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC,
                KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
        prkKey.setKey(prkBuffer, (short) 0, (short) prkBuffer.length);
        hmac.init(prkKey, Signature.MODE_SIGN);

        // Compute new PRK = HMAC(PRK, "rotate" || 0x01)
        byte[] newPrk = new byte[32];
        hmac.sign(input, (short) 0, inputLen, newPrk, (short) 0);
        // Update stored PRK with the new value.
        Util.arrayCopyNonAtomic(newPrk, (short) 0, prkBuffer, (short) 0, (short) newPrk.length);

        // Return the new PRK.
        Util.arrayCopyNonAtomic(prkBuffer, (short) 0, buffer, (short) 0, (short) prkBuffer.length);
        apdu.setOutgoingAndSend((short) 0, (short) prkBuffer.length);
    }
}
