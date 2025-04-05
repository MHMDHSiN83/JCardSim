package com.licel.jcardsim.samples;


import javacard.framework.*;
import javacard.security.RandomData;

public class KeyManagerApplet extends Applet {
    // APDU instruction constants
    private static final byte INS_CREATE_KEY = (byte) 0x10;
    private static final byte INS_READ_KEY   = (byte) 0x20;
    private static final byte INS_UPDATE_KEY = (byte) 0x30;
    private static final byte INS_DELETE_KEY = (byte) 0x40;

    // The size of the key (e.g., 16 bytes for AES-128)
    private static final short KEY_SIZE = 16;

    // Storage for the key (32 bytes for simplicity, can be adjusted)
    private byte[] storedKey;

    private KeyManagerApplet() {
        storedKey = new byte[KEY_SIZE]; // Allocate space for storing the key
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new KeyManagerApplet();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        switch (ins) {
            case INS_CREATE_KEY:
                createKey(apdu);
                break;
            case INS_READ_KEY:
                readKey(apdu);
                break;
            case INS_UPDATE_KEY:
                updateKey(apdu);
                break;
            case INS_DELETE_KEY:
                deleteKey(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * CREATE: Generates a new random key and stores it.
     */
    private void createKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
    
        // Use Java Card's recommended TRNG (True Random Number Generator)
        RandomData randomData = RandomData.getInstance(RandomData.ALG_TRNG);
        randomData.nextBytes(storedKey, (short) 0, (short) KEY_SIZE);
    
        // Copy the generated key into the buffer
        Util.arrayCopyNonAtomic(storedKey, (short) 0, buffer, (short) 0, (short) KEY_SIZE);
        apdu.setOutgoingAndSend((short) 0, (short) KEY_SIZE);
    }
    /**
     * READ: Returns the stored key.
     */
    private void readKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        // Check if the key exists, if not, throw an exception
        if (storedKey == null || storedKey.length == 0) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }

        // Return the stored key to the host
        Util.arrayCopyNonAtomic(storedKey, (short) 0, buffer, (short) 0, (short) KEY_SIZE);
        apdu.setOutgoingAndSend((short) 0, (short) KEY_SIZE);
    }

    /**
     * UPDATE: Updates the stored key with a new key.
     */
    private void updateKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        // Receive the new key from the APDU
        short len = apdu.setIncomingAndReceive();

        if (len != KEY_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Update the stored key
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, storedKey, (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * DELETE: Deletes the stored key (set it to null or reset).
     */
    private void deleteKey(APDU apdu) {
        // Reset the stored key to null (or you can set it to a known value if preferred)
        storedKey = new byte[KEY_SIZE];

        // Respond with success (no data)
        apdu.setOutgoingAndSend((short) 0, (short) 0);
    }
}
