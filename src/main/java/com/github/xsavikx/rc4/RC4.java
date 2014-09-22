package com.github.xsavikx.rc4;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class RC4 {

	private byte[] key = new byte[SBOX_LENGTH - 1];
	private int[] sbox = new int[SBOX_LENGTH];
	private static final int SBOX_LENGTH = 256;
	private static final int KEY_MIN_LENGTH = 5;

	public RC4() {
		reset();
	}

	public RC4(String key) throws InvalidKeyException {
		this();
		setKey(key);
	}

	private void reset() {
		for (int i = 0; i < key.length; i++)
			key[i] = 0;
		Arrays.fill(sbox, 0);
	}

	public byte[] encryptMessage(String message, Charset charset, String key)
			throws InvalidKeyException {
		reset();
		setKey(key);
		byte[] crypt = crypt(message.getBytes());
		reset();
		return crypt;
	}

	public byte[] encryptMessage(String message, String key)
			throws InvalidKeyException {
		return encryptMessage(message, StandardCharsets.UTF_8, key);
	}

	public String decryptMessage(byte[] message, Charset charset, String key)
			throws InvalidKeyException {
		reset();
		setKey(key);
		byte[] msg = crypt(message);
		reset();
		return new String(msg);
	}

	public String decryptMessage(byte[] message, String key)
			throws InvalidKeyException {
		return decryptMessage(message, StandardCharsets.UTF_8, key);
	}

	public byte[] crypt(final byte[] msg) {
		sbox = initSBox(key);
		byte[] code = new byte[msg.length];
		int i = 0;
		int j = 0;
		for (int n = 0; n < msg.length; n++) {
			i = (i + 1) % SBOX_LENGTH;
			j = (j + sbox[i]) % SBOX_LENGTH;
			swap(i, j, sbox);
			int rand = sbox[(sbox[i] + sbox[j]) % SBOX_LENGTH];
			code[n] = (byte) (rand ^ msg[n]);
		}
		return code;
	}

	private int[] initSBox(byte[] key) {
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

		this.key = key.getBytes();
	}

}

class InvalidKeyException extends Exception {

	private static final long serialVersionUID = 1L;

	public InvalidKeyException(String message) {
		super(message);
	}

}