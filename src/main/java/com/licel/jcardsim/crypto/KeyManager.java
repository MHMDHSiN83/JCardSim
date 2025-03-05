package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyBuilder;

import java.util.HashMap;
import java.util.Map;

/**
 * Design an internal secure storage for SIM-like key lifecycle management.
 */
public class KeyManager {

    private static final Map<Byte, Key> keyStore = new HashMap<>();

    /**
     * Creates or retrieves a cryptographic key for the given parameters.
     * @param keyType The type of key to generate.
     * @param keyLength The length of the key in bits.
     * @param keyEncryption Whether the key should support encryption.
     * @return The generated or retrieved key.
     * @throws CryptoException If the key parameters are invalid.
     */
    public static Key getKey(byte keyType, short keyLength, boolean keyEncryption) throws CryptoException {
        byte keyId = generateKeyId(keyType, keyLength);
        if (keyStore.containsKey(keyId)) {
            return keyStore.get(keyId);
        }

        Key key = buildKey(keyType, keyLength, keyEncryption);
        keyStore.put(keyId, key);
        return key;
    }

    /**
     * Deletes a key from the store.
     * @param keyType The type of key to delete.
     * @param keyLength The length of the key.
     */
    public static void deleteKey(byte keyType, short keyLength) {
        byte keyId = generateKeyId(keyType, keyLength);
        keyStore.remove(keyId);
    }

    /**
     * Updates an existing key by replacing it with a new one.
     * @param keyType The type of key.
     * @param keyLength The length of the key.
     * @param keyEncryption Whether encryption should be supported.
     * @throws CryptoException If the new key cannot be created.
     */
    public static void updateKey(byte keyType, short keyLength, boolean keyEncryption) throws CryptoException {
        deleteKey(keyType, keyLength);
        getKey(keyType, keyLength, keyEncryption);
    }

    /**
     * Internal method for creating new keys.
     */
    private static Key buildKey(byte keyType, short keyLength, boolean keyEncryption) throws CryptoException {
        Key key = null;
        switch (keyType) {
            case KeyBuilder.TYPE_DES:
                if (keyLength != 64 && keyLength != 128 && keyLength != 192) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                }
                key = new SymmetricKeyImpl(keyType, keyLength);
                break;

            case KeyBuilder.TYPE_RSA_PUBLIC:
                key = new RSAKeyImpl(false, keyLength);
                break;

            case KeyBuilder.TYPE_RSA_PRIVATE:
                key = new RSAKeyImpl(true, keyLength);
                break;

            case KeyBuilder.TYPE_AES:
                if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                }
                key = new SymmetricKeyImpl(keyType, keyLength);
                break;

            default:
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                break;
        }
        return key;
    }

    /**
     * Generates a unique identifier for a key type and length.
     */
    private static byte generateKeyId(byte keyType, short keyLength) {
        return (byte) (keyType ^ (keyLength & 0xFF));
    }
}
