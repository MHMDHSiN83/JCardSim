package com.licel.jcardsim.samples;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.JCardSimProvider;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;

import javax.smartcardio.*;

public class test {
    public static void main(String[] args) {
        CardSimulator simulator = new CardSimulator();

// 2. install applet
    AID appletAID = AIDUtil.create("F000000001");
    simulator.installApplet(appletAID, HelloWorldApplet.class);

    // 3. select applet
    simulator.selectApplet(appletAID);

    // 4. send APDU
    CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x01, 0x00, 0x00);
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    
    // assertEquals(0x9000, response.getSW());
    // 5. check response
    }
}
