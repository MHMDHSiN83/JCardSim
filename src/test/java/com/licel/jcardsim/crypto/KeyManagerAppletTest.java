package com.licel.jcardsim.crypto;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import static org.junit.Assert.*;

import com.licel.jcardsim.samples.KeyManagerApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import junit.framework.TestCase;

import javax.smartcardio.*;

public class KeyManagerAppletTest extends TestCase {

    public void testCreateKey() {
        CardSimulator simulator = new CardSimulator();
        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, KeyManagerApplet.class);
        simulator.selectApplet(appletAID);

        CommandAPDU createKeyAPDU = new CommandAPDU(0x00, 0x10, 0x00, 0x00);
        ResponseAPDU createResponse = simulator.transmitCommand(createKeyAPDU);

        System.out.println("Created Key: " + bytesToHex(createResponse.getData()));
        assertEquals(ISO7816.SW_NO_ERROR, (short) createResponse.getSW());
        assertEquals(16, createResponse.getData().length);
    }

    public void testReadKey() {
        CardSimulator simulator = new CardSimulator();
        AID appletAID = AIDUtil.create("F000000002");
        simulator.installApplet(appletAID, KeyManagerApplet.class);
        simulator.selectApplet(appletAID);

        CommandAPDU createKeyAPDU = new CommandAPDU(0x00, 0x10, 0x00, 0x00);
        simulator.transmitCommand(createKeyAPDU);

        CommandAPDU readKeyAPDU = new CommandAPDU(0x00, 0x20, 0x00, 0x00);
        ResponseAPDU readResponse = simulator.transmitCommand(readKeyAPDU);

        assertEquals(ISO7816.SW_NO_ERROR, (short) readResponse.getSW());
        assertEquals(16, readResponse.getData().length);
    }

    public void testUpdateKey() {
        CardSimulator simulator = new CardSimulator();
        AID appletAID = AIDUtil.create("F000000003");
        simulator.installApplet(appletAID, KeyManagerApplet.class);
        simulator.selectApplet(appletAID);

        CommandAPDU createKeyAPDU = new CommandAPDU(0x00, 0x10, 0x00, 0x00);
        simulator.transmitCommand(createKeyAPDU);

        byte[] newKey = new byte[16];
        for (byte i = 0; i < 16; i++) {
            newKey[i] = i;
        }

        CommandAPDU updateKeyAPDU = new CommandAPDU(0x00, 0x30, 0x00, 0x00, newKey);
        ResponseAPDU updateResponse = simulator.transmitCommand(updateKeyAPDU);
        assertEquals(ISO7816.SW_NO_ERROR, (short) updateResponse.getSW());

        CommandAPDU readKeyAPDU = new CommandAPDU(0x00, 0x20, 0x00, 0x00);
        ResponseAPDU readResponse = simulator.transmitCommand(readKeyAPDU);
        assertEquals(ISO7816.SW_NO_ERROR, (short) readResponse.getSW());
        assertArrayEquals(newKey, readResponse.getData());
    }

    public void testDeleteKey() {
        CardSimulator simulator = new CardSimulator();
        AID appletAID = AIDUtil.create("F000000004");
        simulator.installApplet(appletAID, KeyManagerApplet.class);
        simulator.selectApplet(appletAID);

        CommandAPDU createKeyAPDU = new CommandAPDU(0x00, 0x10, 0x00, 0x00);
        simulator.transmitCommand(createKeyAPDU);

        CommandAPDU deleteKeyAPDU = new CommandAPDU(0x00, 0x40, 0x00, 0x00);
        ResponseAPDU deleteResponse = simulator.transmitCommand(deleteKeyAPDU);
        assertEquals(ISO7816.SW_NO_ERROR, (short) deleteResponse.getSW());

        // Optionally verify that key has been cleared (will return all zeros)
        CommandAPDU readKeyAPDU = new CommandAPDU(0x00, 0x20, 0x00, 0x00);
        ResponseAPDU readResponse = simulator.transmitCommand(readKeyAPDU);
        assertEquals(ISO7816.SW_NO_ERROR, (short) readResponse.getSW());

        byte[] expectedCleared = new byte[16]; // All zeros
        assertArrayEquals(expectedCleared, readResponse.getData());
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
