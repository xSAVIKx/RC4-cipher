package com.github.xsavikx.rc4;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class RC4 {
	/**
	 * Key array
	 */
	private byte[] key = new byte[SBOX_LENGTH - 1];
	/**
	 * Sbox
	 */
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

	/**
	 * Encrypt given message String with given Charset and key
	 * 
	 * @param message
	 *            message to be encrypted
	 * @param charset
	 *            charset of message
	 * @param key
	 *            key
	 * @return encrypted message
	 * @throws InvalidKeyException
	 *             if key length is smaller than 5 or bigger than 255
	 */
	public byte[] encryptMessage(String message, Charset charset, String key)
			throws InvalidKeyException {
		reset();
		setKey(key);
		byte[] crypt = crypt(message.getBytes());
		reset();
		return crypt;
	}

	/**
	 * Encrypt given message String with given Key and pre-defined UTF-8 charset
	 * 
	 * @param message
	 *            message to be encrypted
	 * @param key
	 *            key
	 * @return encrypted message
	 * @throws InvalidKeyException
	 *             if key length is smaller than 5 or bigger than 255
	 * @see StandardCharsets
	 */
	public byte[] encryptMessage(String message, String key)
			throws InvalidKeyException {
		return encryptMessage(message, StandardCharsets.UTF_8, key);
	}

	/**
	 * Decrypt given byte[] message array with given charset and key
	 * 
	 * @param message
	 *            message to be decrypted
	 * @param charset
	 *            charset of message
	 * @param key
	 *            key
	 * @return string in given charset
	 * @throws InvalidKeyException
	 *             if key length is smaller than 5 or bigger than 255
	 */
	public String decryptMessage(byte[] message, Charset charset, String key)
			throws InvalidKeyException {
		reset();
		setKey(key);
		byte[] msg = crypt(message);
		reset();
		return new String(msg);
	}

	/**
	 * Decrypt given byte[] message array with given key and pre-defined UTF-8
	 * charset
	 * 
	 * @param message
	 *            message to be decrypted
	 * @param key
	 *            key
	 * @return string in given charset
	 * @throws InvalidKeyException
	 *             if key length is smaller than 5 or bigger than 255
	 * @see StandardCharsets
	 */
	public String decryptMessage(byte[] message, String key)
			throws InvalidKeyException {
		return decryptMessage(message, StandardCharsets.UTF_8, key);
	}

	/**
	 * Crypt given byte array. Be aware, that you must init key, before using
	 * crypt.
	 * 
	 * @param msg
	 *            array to be crypt
	 * @return crypted byte array
	 * @see <a
	 *      href="http://en.wikipedia.org/wiki/RC4#Pseudo-random_generation_algorithm_.28PRGA.29">Pseudo-random
	 *      generation algorithm</a>
	 */
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

	/**
	 * Initialize SBOX with given key. Key-scheduling algorithm
	 * 
	 * @param key
	 *            key
	 * @return sbox int array
	 * @see <a
	 *      href="http://en.wikipedia.org/wiki/RC4#Key-scheduling_algorithm_.28KSA.29">Wikipedia.
	 *      Init sbox</a>
	 */
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

	/**
	 * Setup key
	 * 
	 * @param key
	 *            key to be setup
	 * @throws InvalidKeyException
	 *             if key length is smaller than 5 or bigger than 255
	 */
	public void setKey(String key) throws InvalidKeyException {
		if (!(key.length() >= KEY_MIN_LENGTH && key.length() < SBOX_LENGTH)) {
			throw new InvalidKeyException("Key length has to be between "
					+ KEY_MIN_LENGTH + " and " + (SBOX_LENGTH - 1));
		}

		this.key = key.getBytes();
	}

}

/**
 * Exception made for recognise invalid keys
 * 
 * @author Iurii Sergiichuk
 */
class InvalidKeyException extends Exception {

	private static final long serialVersionUID = -2412232436238451574L;

	public InvalidKeyException(String message) {
		super(message);
	}

}