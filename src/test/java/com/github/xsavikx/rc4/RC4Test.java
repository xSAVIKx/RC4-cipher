package com.github.xsavikx.rc4;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

public class RC4Test {
	private RC4 rc4;
	private String message;
	private String key;

	@Before
	public void setUp() throws Exception {
		rc4 = new RC4();
		message = "Hello, World!";
		key = "This is pretty long key";
	}

	@Test
	public void testCryptMessage() throws InvalidKeyException {
		char[] crypt = rc4.encryptMessage(message, key);
		String msg = rc4.decryptMessage(crypt, key);
		assertEquals(message, msg);
	}

}
