package com.emc.settlement.common;

import java.io.IOException;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

/**
 * This class overrides the sem-web.jar encryption classes
 * This is to upgrade the security encryption from DES to AES
 * @author jan.balbin
 *
 */
public class EncryptionService {

	private static final Logger logger = Logger.getLogger(EncryptionService.class);
	
	public static final String EMCKey="EMCKey";

	/**
	* This method is used by the EncryptionApp to encrypt the string.
	* @parm - strToEncrypt string to encrypt
	* @parm - encryptionKey encryption key
	* @return string
	*/
	public static String encryptString(String strToEncrypt,String encryptionKey) throws Exception
	{
		logger.info("===== EncryptionService.encryptString(strToEncrypt,encryptionKey): "+strToEncrypt+" - "+encryptionKey);
		
		String encryptedString = "";
		EncryptionEngine engine = new EncryptionEngine();
		try {
			synchronized (EncryptionService.class) {
				
				String encryptionKeyValue = new String(new Base64().decode(encryptionKey));
				
				logger.info("===== encryptionKeyValue: "+encryptionKeyValue);
				
				encryptedString = engine.encrypt(strToEncrypt, encryptionKeyValue);
				
				logger.info("===== encryptedString: "+encryptedString);
			}

		}
		catch(Exception ex){
			logger.error("===== EncryptionService.encryptString(): Exception getting the encryption method: "+ex);
			
			throw new Exception ("EncryptionService: Exception getting the encryption method="+ex.getMessage());
		} finally {
			engine = null;
		}
	 	return encryptedString;
	}

	/**
	* This method is used by the EncryptionService to decrypt the string.
	* @parm - encryptedStr encrypted string
	* @parm - encryptionKey encryption key
	* @return string
	*/
	public static String decryptString(String encryptedStr,String encryptionKey) throws Exception
	{
		logger.info("===== EncryptionService.decryptString(encryptedStr,encryptionKey): "+encryptedStr+" - "+encryptionKey);
		
		String decryptedString = "";
		EncryptionEngine engine = new EncryptionEngine();
		try{
			synchronized (EncryptionService.class) {
				
				String encryptionKeyValue = new String(new Base64().decode(encryptionKey));
				
				logger.info("===== encryptionKeyValue: "+encryptionKeyValue);
				
				decryptedString = engine.decrypt(encryptedStr, encryptionKeyValue);
				
				logger.info("===== decryptedString: "+decryptedString);
			}
		}
		catch(Exception ex){
			throw new Exception ("EncryptionService: Exception getting the decryption method="+ex.getMessage());
		} finally {
			engine = null;
		}
	 	return decryptedString;
	}
	/**
	* This method returns the value for the EncryptionKey from the properties supplied.
	* @parm - propsApps name of the Property from where the value will be returned.
	* @return String
	*/
	public static String getEncryptionKeyValue(EncryptionProperties propsApps) throws IOException {

		String  EMCDecryptKeyValue="";
		try{
			EMCDecryptKeyValue=(String) propsApps.getPropertyValue(EMCKey);
		}
		catch(Exception ex){
			throw new IOException("EncryptionService: EMC Key is not specifed in the file AppsPasswordConfig file. "+ex.getMessage());
		}
		return EMCDecryptKeyValue;
	}
}