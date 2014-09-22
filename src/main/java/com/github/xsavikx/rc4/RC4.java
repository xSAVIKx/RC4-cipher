package com.github.xsavikx.rc4;

import java.util.Arrays;

public class RC4 {

	private char[] key;
	private int[] sbox;
	private static final int SBOX_LENGTH = 256;
	private static final int KEY_MIN_LENGTH = 5;

	public static void main(String[] args) {
		try {
			RC4 rc4 = new RC4("testkey");
			char[] result = rc4.crypt("hello there".toCharArray());
			System.out.println("encrypted string:\n" + new String(result));
			System.out.println("decrypted string:\n"
					+ new String(rc4.crypt(result)));
		} catch (InvalidKeyException e) {
			System.err.println(e.getMessage());
		}
	}

	public RC4() {
		key = new char[SBOX_LENGTH - 1];
		sbox = new int[SBOX_LENGTH];
		reset();
	}

	public RC4(String key) throws InvalidKeyException {
		this();
		setKey(key);
	}

	private void reset() {
		Arrays.fill(key, (char) 0);
		Arrays.fill(sbox, 0);
	}

	public char[] encryptMessage(String message, String key)
			throws InvalidKeyException {
		reset();
		setKey(key);
		char[] crypt = crypt(message.toCharArray());
		reset();
		return crypt;
	}

	public String decryptMessage(char[] message, String key)
			throws InvalidKeyException {
		reset();
		setKey(key);
		char[] msg = crypt(message);
		reset();
		return String.valueOf(msg);
	}

	public char[] crypt(final char[] msg) {
		sbox = initSBox(key);
		char[] code = new char[msg.length];
		int i = 0;
		int j = 0;
		for (int n = 0; n < msg.length; n++) {
			i = (i + 1) % SBOX_LENGTH;
			j = (j + sbox[i]) % SBOX_LENGTH;
			swap(i, j, sbox);
			int rand = sbox[(sbox[i] + sbox[j]) % SBOX_LENGTH];
			code[n] = (char) (rand ^ (int) msg[n]);
		}
		return code;
	}

	private int[] initSBox(char[] key) {
		int[] sbox = new int[SBOX_LENGTH];
		int j = 0;

		for (int i = 0; i < SBOX_LENGTH; i++) {
			sbox[i] = i;
		}

		for (int i = 0; i < SBOX_LENGTH; i++) {
			j = (j + sbox[i] + key[i % key.length]) % SBOX_LENGTH;
			swap(i, j, sbox);
		}
		return sbox;
	}

	private void swap(int i, int j, int[] sbox) {
		int temp = sbox[i];
		sbox[i] = sbox[j];
		sbox[j] = temp;
	}

	public void setKey(String key) throws InvalidKeyException {
		if (!(key.length() >= KEY_MIN_LENGTH && key.length() < SBOX_LENGTH)) {
			throw new InvalidKeyException("Key length has to be between "
					+ KEY_MIN_LENGTH + " and " + (SBOX_LENGTH - 1));
		}

		this.key = key.toCharArray();
	}

}

class InvalidKeyException extends Exception {

	private static final long serialVersionUID = 1L;

	public InvalidKeyException(String message) {
		super(message);
	}

}