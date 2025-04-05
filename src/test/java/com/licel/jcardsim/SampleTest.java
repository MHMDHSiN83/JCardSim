package com.licel.jcardsim;

import com.licel.jcardsim.crypto.HKDF;
import com.licel.jcardsim.samples.HKDFManagerApplet;
import com.licel.jcardsim.samples.HelloWorldApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.utils.ByteUtil;
import javacard.framework.AID;
import junit.framework.TestCase;

import javax.smartcardio.*;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

/**
 * Contains all listing from the documentation
 */
public class SampleTest extends TestCase {
        // public static void main(String args[]) {
        //     testHKDFApplet();  
        // }

    public static void testCodeListingReadme() {
        // 1. Create simulator
        CardSimulator simulator = new CardSimulator();
        
        // 2. Install applet
        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, HelloWorldApplet.class);
        
        // 3. Select applet
        simulator.selectApplet(appletAID);
        
        // 4. Send APDU
        CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x01, 0x00, 0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        
        System.err.println(response.toString());
        // 5. Check response status word
        assertEquals(0x9000, response.getSW());
    }

    public void testCodeListing1() {
        // 1. Create simulator
        CardSimulator simulator = new CardSimulator();

        // 2. Install applet
        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, HelloWorldApplet.class);

        // 3. Select applet
        simulator.selectApplet(appletAID);

        // 4. Send APDU
        CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x01, 0x00, 0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        // 5. Check response status word
        assertEquals(0x9000, response.getSW());
    }


    public static void testCodeListing2() {
        CardSimulator simulator = new CardSimulator();

        byte[] appletAIDBytes = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9};
        AID appletAID = new AID(appletAIDBytes, (short) 0, (byte) appletAIDBytes.length);
        simulator.installApplet(appletAID, HelloWorldApplet.class);
        simulator.selectApplet(appletAID);

        // test NOP
        ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(0x00, 0x02, 0x00, 0x00));
        System.out.println(response.toString());
        assertEquals(0x9000, response.getSW());

        // test hello world from card
        response = simulator.transmitCommand(new CommandAPDU(0x00, 0x01, 0x00, 0x00));
        System.out.println(response.toString());
        System.out.println(new String(response.getData()));

        assertEquals(0x9000, response.getSW());
        assertEquals("Hello world !", new String(response.getData()));

        // test echo
        CommandAPDU echo = new CommandAPDU(0x00, 0x01, 0x01, 0x00, ("Hello javacard world !").getBytes());
        response = simulator.transmitCommand(echo);
        System.out.println(response.toString());
        System.out.println(new String(response.getData()));

        assertEquals(0x9000, response.getSW());
        assertEquals("Hello javacard world !", new String(response.getData()));
    }

    public void testCodeListing3() {
        CardSimulator simulator = new CardSimulator();

        byte[] appletAIDBytes = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9};
        AID appletAID = new AID(appletAIDBytes, (short) 0, (byte) appletAIDBytes.length);

        simulator.installApplet(appletAID, HelloWorldApplet.class);
        simulator.selectApplet(appletAID);

        // test NOP
        byte[] response = simulator.transmitCommand(new byte[]{0x00, 0x02, 0x00, 0x00});
        ByteUtil.requireSW(response, 0x9000);
    }

    public void testCodeListing4() {
        // AID from byte array
        AID applet1AID = AIDUtil.create(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9});

        // AID form String
        AID applet2AID = AIDUtil.create("010203040506070809");

        assertEquals(applet1AID, applet2AID);

        // String to byte array
        String hexString = ByteUtil.hexString(new byte[]{0,2,0,0});

        // byte array from String
        byte[] bytes = ByteUtil.byteArray("00 02 00 00");

        assertEquals("00020000", hexString);
        assertEquals("00020000", ByteUtil.hexString(bytes));
    }

    public void testCodeListing5() throws CardException {
        // 1. Create simulator and install applet
        CardSimulator simulator = new CardSimulator();
        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, HelloWorldApplet.class);

        // 2. Create Terminal
        CardTerminal terminal = CardTerminalSimulator.terminal(simulator);

        // 3. Connect to Card
        Card card = terminal.connect("T=1");
        CardChannel channel = card.getBasicChannel();

        // 4. Select applet
        CommandAPDU selectCommand = new CommandAPDU(AIDUtil.select(appletAID));
        channel.transmit(selectCommand);

        // 5. Send APDU
        CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x01, 0x00, 0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        // 6. Check response status word
        assertEquals(0x9000, response.getSW());
    }

    public void testCodeListing6() throws CardException {
        // Obtain CardTerminal
        CardTerminals cardTerminals = CardTerminalSimulator.terminals("My terminal 1", "My terminal 2");
        CardTerminal terminal1 = cardTerminals.getTerminal("My terminal 1");
        CardTerminal terminal2 = cardTerminals.getTerminal("My terminal 2");

        assertEquals(false, terminal1.isCardPresent());
        assertEquals(false, terminal2.isCardPresent());

        // Create simulator and install applet
        CardSimulator simulator = new CardSimulator();
        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, HelloWorldApplet.class);

        // Insert Card into "My terminal 1"
        simulator.assignToTerminal(terminal1);
        assertEquals(true, terminal1.isCardPresent());
        assertEquals(false, terminal2.isCardPresent());
    }

    public void testCodeListing7() throws CardException, NoSuchAlgorithmException {
        // Register provider
        if (Security.getProvider("CardTerminalSimulator") == null) {
            Security.addProvider(new CardTerminalSimulator.SecurityProvider());
        }

        // Get TerminalFactory
        TerminalFactory factory = TerminalFactory.getInstance("CardTerminalSimulator", null);
        CardTerminals cardTerminals = factory.terminals();

        // Get CardTerminal
        CardTerminal terminal = cardTerminals.getTerminal("jCardSim.Terminal");
        assertNotNull(terminal);
    }

    public void testCodeListing8() throws CardException, NoSuchAlgorithmException {
        // Register provider
        if (Security.getProvider("CardTerminalSimulator") == null) {
            Security.addProvider(new CardTerminalSimulator.SecurityProvider());
        }

        // Get TerminalFactory with custom names
        String[] names = new String[] {"My terminal 1", "My terminal 2"};
        TerminalFactory factory = TerminalFactory.getInstance("CardTerminalSimulator", names);
        CardTerminals cardTerminals = factory.terminals();
        assertNotNull(cardTerminals.getTerminal("My terminal 1"));
        assertNotNull(cardTerminals.getTerminal("My terminal 2"));
    }

    public static void testCodeListing9() {
        String ikmHex = "6a2b3c4d5e6f7a8b9cadbecfd0e1f2031425364758697a8b9cadbecfd0e1f203";
        byte[] ikm = hexStringToByteArray(ikmHex);
        byte[] salt = null;

        // Print the byte array to verify the conversion
        // System.out.println(Arrays.toString(ikm));
        // System.out.println(Arrays.toString(toUnsignedBytes(ikm)));

        // Register provider
        byte[] pseudoRandomKey = HKDF.fromHmacSha256().extract(salt, ikm);
        byte[] outputKeyingMaterial = HKDF.fromHmacSha256().expand(pseudoRandomKey, null, 64);
        System.out.println(Arrays.toString(outputKeyingMaterial));
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
    
    public static int[] toUnsignedBytes(byte[] bytes) {
        int[] unsignedBytes = new int[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            unsignedBytes[i] = bytes[i] & 0xFF;
        }
        return unsignedBytes;
    }

    public static void testHKDFApplet() {
        // Initialize the simulator.
        CardSimulator simulator = new CardSimulator();

        // Define an AID for the HKDFManagementApplet.
        byte[] appletAIDBytes = new byte[]{(byte)0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, 0x01};
        AID appletAID = new AID(appletAIDBytes, (short) 0, (byte) appletAIDBytes.length);
        
        // Install and select the HKDFManagementApplet.
        simulator.installApplet(appletAID, HKDFManagerApplet.class);
        simulator.selectApplet(appletAID);

        // ---- Test HKDF-Extract ----
        // Prepare sample Input Keying Material (IKM)
        byte[] ikm = new byte[]{ 
            0x01, 0x02, 0x03, 0x04, 
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C,
            0x0D, 0x0E, 0x0F, 0x10 
        };
        // INS_EXTRACT is defined as 0x10.
        CommandAPDU extractAPDU = new CommandAPDU(0x00, 0x10, 0x00, 0x00, ikm);
        ResponseAPDU extractResponse = simulator.transmitCommand(extractAPDU);
        System.out.println("Extract Response: " + extractResponse.toString());
        byte[] prkBefore = extractResponse.getData();
        // Expect a 32-byte pseudorandom key (PRK) with status word 0x9000.
        System.out.println(prkBefore);
        // assertEquals(0x9000, extractResponse.getSW());
        // assertEquals(32, prkBefore.length);

        // ---- Test HKDF-Expand ----
        // Use an example info string, e.g., "aes-key"
        byte[] info = "aes-key".getBytes();
        // INS_EXPAND is defined as 0x20.
        CommandAPDU expandAPDU = new CommandAPDU(0x00, 0x20, 0x00, 0x00, info);
        ResponseAPDU expandResponse = simulator.transmitCommand(expandAPDU);
        System.out.println("Expand Response: " + expandResponse.toString());
        byte[] derivedKey = expandResponse.getData();

        // Expect a derived key of 16 bytes with status word 0x9000.
        System.out.println(derivedKey);
        // assertEquals(0x9000, expandResponse.getSW());
        // assertEquals(16, derivedKey.length);

        // ---- Test HKDF-Rotate ----
        // INS_ROTATE is defined as 0x30.
        CommandAPDU rotateAPDU = new CommandAPDU(0x00, 0x30, 0x00, 0x00);
        ResponseAPDU rotateResponse = simulator.transmitCommand(rotateAPDU);
        System.out.println("Rotate Response: " + rotateResponse.toString());
        byte[] prkAfter = rotateResponse.getData();
        
        // Expect a new 32-byte PRK with status word 0x9000.
        System.out.println(prkAfter);
        // assertEquals(0x9000, rotateResponse.getSW());
        // assertEquals(32, prkAfter.length);

        // Verify that the rotated PRK is different from the original PRK.
        // assertFalse(java.util.Arrays.equals(prkBefore, prkAfter));
    }
}
