package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import junit.framework.TestCase;

/**
 * JUnit 3 test for KeyManager
 */
public class KeyManagerTest extends TestCase {

    public KeyManagerTest(String testName) {
        super(testName);
    }

    protected void setUp() throws Exception {
        super.setUp();
    }

    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test generating an AES key.
     */
    public void testGenerateKey() {
        try {
            Key aesKey = KeyManager.getKey(KeyBuilder.TYPE_AES, (short) 128, true);
            assertNotNull(aesKey);
            assertEquals(KeyBuilder.TYPE_AES, aesKey.getType());
        } catch (CryptoException e) {
            fail("CryptoException thrown: " + e.getReason());
        }
    }

    /**
     * Test retrieving an AES key from KeyManager.
     */
    public void testGetKey() {
        try {
            Key aesKey = KeyManager.getKey(KeyBuilder.TYPE_AES, (short) 128, true);
            assertNotNull(aesKey);
        } catch (CryptoException e) {
            fail("CryptoException thrown: " + e.getReason());
        }
    }

    /**
     * Test deleting a key.
     */
    public void testDeleteKey() {
        try {
            KeyManager.getKey(KeyBuilder.TYPE_AES, (short) 128, true); // Create key
            KeyManager.deleteKey(KeyBuilder.TYPE_AES, (short) 128); // Delete key
            Key deletedKey = KeyManager.getKey(KeyBuilder.TYPE_AES, (short) 128, true); // Should be a new instance
            assertNotNull(deletedKey);
        } catch (CryptoException e) {
            fail("CryptoException thrown: " + e.getReason());
        }
    }

    /**
     * Test updating a key.
     */
    public void testUpdateKey() {
        try {
            KeyManager.getKey(KeyBuilder.TYPE_AES, (short) 128, true); // Create key
            KeyManager.updateKey(KeyBuilder.TYPE_AES, (short) 128, true); // Update key
            Key updatedKey = KeyManager.getKey(KeyBuilder.TYPE_AES, (short) 128, true);
            assertNotNull(updatedKey);
        } catch (CryptoException e) {
            fail("CryptoException thrown: " + e.getReason());
        }
    }
}