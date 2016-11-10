package com.github.xsavikx.rc4;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class RC4Test {

    @Test
    public void testCryptMessage() {
        RC4 rc4 = new RC4();
        String message = "Hello, World!";
        String key = "This is pretty long key";
        byte[] crypt = rc4.encryptMessage(message, key);
        String msg = rc4.decryptMessage(crypt, key);
        assertEquals(message, msg);
    }

    @Test
    public void testCryptWithNonEnglishCharacters() {
        String message = "Привет, Мир!";
        String key = "Это довольно длинный ключ";
        RC4 rc4 = new RC4(key);
        byte[] crypt = rc4.crypt(message.getBytes());
        byte[] msg = rc4.crypt(crypt);
        assertEquals(message, new String(msg));
    }

    @Test(expected = InvalidKeyException.class)
    public void testSetKeyShouldThrowInvalidKeyExceptionWithTooSmallKey() {
        new RC4("");
    }

    @Test(expected = InvalidKeyException.class)
    public void testSetKeyShouldThrowInvalidKeyExceptionWithTooBigKey() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 512; i++) {
            sb.append('a');
        }
        RC4 rc4 = new RC4();
        rc4.setKey(sb.toString());
    }

}
