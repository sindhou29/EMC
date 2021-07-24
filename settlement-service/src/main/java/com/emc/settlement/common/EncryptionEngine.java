package com.emc.settlement.common;

import java.nio.ByteBuffer;

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

//AES Upgrade
import org.apache.commons.codec.binary.Base64;

/**
 * This class overrides the sem-web.jar encryption classes
 * This is to upgrade the security encryption from DES to AES
 * @author jan.balbin
 *
 */
public class EncryptionEngine
{

	private static final String	UNICODE_FORMAT	= "UTF8";
	
	public static final String AES_ENCRYPTION_SCHEME = "AES";
	public static final String ALGORITHM_PBKDF2WITHHMACSHA1 = "PBKDF2WithHmacSHA1";
	public static final String CIPHER_ENCRYPTION_SCHEME = "AES/CBC/PKCS5Padding";	

	/**
	 * AES encrypt function
	 * @param word
	 * @param secureKey
	 * @return
	 * @throws Exception
	 */
	public String encrypt(String word, String secureKey) throws Exception {
		byte[] ivBytes;

		
		SecureRandom random = new SecureRandom();
		byte bytes[] = new byte[20];
		random.nextBytes(bytes);
		byte[] saltBytes = bytes;

		// Frame SecretKeySpec
		SecretKeySpec secret = getSecretKeySpec(secureKey, saltBytes);

		// Encryption logic
		Cipher cipher = Cipher.getInstance(CIPHER_ENCRYPTION_SCHEME);
		cipher.init(Cipher.ENCRYPT_MODE, secret);
		AlgorithmParameters params = cipher.getParameters();
		ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
		byte[] encryptedTextBytes = cipher.doFinal(word.getBytes(UNICODE_FORMAT));

		// Append salt and vi
		byte[] buffer = new byte[saltBytes.length + ivBytes.length + encryptedTextBytes.length];
		System.arraycopy(saltBytes, 0, buffer, 0, saltBytes.length);
		System.arraycopy(ivBytes, 0, buffer, saltBytes.length, ivBytes.length);
		System.arraycopy(encryptedTextBytes, 0, buffer, saltBytes.length + ivBytes.length, encryptedTextBytes.length);
		return new Base64().encodeToString(buffer);
	}

	/**
	 * AES secret key spec function
	 * @param secureKey
	 * @param saltBytes
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private SecretKeySpec getSecretKeySpec(String secureKey, byte[] saltBytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM_PBKDF2WITHHMACSHA1);
		PBEKeySpec spec = new PBEKeySpec(secureKey.toCharArray(), saltBytes, 65556, 128);
		SecretKey secretKey = factory.generateSecret(spec);
		return new SecretKeySpec(secretKey.getEncoded(), AES_ENCRYPTION_SCHEME);

	}

	/**
	 * AES decrypt function
	 * @param encryptedText
	 * @param secureKey
	 * @return
	 * @throws Exception
	 */
	public String decrypt(String encryptedText, String secureKey) throws Exception {

		Cipher cipher = Cipher.getInstance(CIPHER_ENCRYPTION_SCHEME);
		
		// Get rid off the salt and iv
		ByteBuffer buffer = ByteBuffer.wrap(new Base64().decode(encryptedText));
		byte[] saltBytes = new byte[20];
		buffer.get(saltBytes, 0, saltBytes.length);
		byte[] ivBytes1 = new byte[cipher.getBlockSize()];
		buffer.get(ivBytes1, 0, ivBytes1.length);
		byte[] encryptedTextBytes = new byte[buffer.capacity() - saltBytes.length - ivBytes1.length];

		buffer.get(encryptedTextBytes);
		
		// Frame SecretKeySpec
		SecretKeySpec secret = getSecretKeySpec(secureKey, saltBytes);
		
		cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes1));
		byte[] decryptedTextBytes = null;

		try {
			decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {			
			e.printStackTrace();
		}

		return new String(decryptedTextBytes);
	}	
	
}

