package routines;

import java.io.File;
import java.io.FileInputStream;
import java.util.Properties;

import javax.xml.bind.DatatypeConverter;

import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;

public class TalendEncryption {

	private static String defaultSeed = "defaultsecretpassword";
	private static StandardPBEByteEncryptor  encryptor;
	private static String seed;
	
	/**
     * Initialise the TalendEncryption Jasypt encryptor key.
     *
     * @param filepath the path of the properties file from which to load the encryptor key.
     * @return void
     *
     * {talendTypes} Object
     *
     * {Category} TalendEncryption
     *
     * {param} string("/opt/talend/encryption.properties") filepath : properties file to load
     *
     * {example} initialize("/opt/talend/encryption.properties") #
     */
	public static void initialize(String filepath) throws Exception{	
		encryptor = new StandardPBEByteEncryptor();
		encryptor.setAlgorithm("PBEWithMD5AndTripleDES");
		
		try {
			File file = new File(filepath);
			FileInputStream fileInput = new FileInputStream(file);
			
			
			Properties properties = new Properties();
			properties.load(fileInput);
			fileInput.close();
			
			seed = new StringBuilder(properties.getProperty("Secret")).toString();//.reverse().toString();
			
			encryptor.setPassword(seed);
			
		} catch (Exception e){
			encryptor.setPassword(defaultSeed);
			//throw e;
		}		
	}

	 /**
     * Converts an unencrypted value in an encrypted one using Jasypt encryptionlibrary
     *
     * {talendTypes} String | String
     *
     * {Category} StringHandling
     *
     * {param} String value: String value
     *
     * {example} secretpassword=ENC(x1387yx=)
     *
     */
    public static String encrypt (String message, String filepath) throws Exception {

    	initialize(filepath);
    	return ("ENC("+ DatatypeConverter.printBase64Binary(encryptor.encrypt(message.getBytes())) + ")").replace("=", ";");
 
    }
    
    /**
     * Converts an encrypted value to an decrypted one using Jasypt encryptionlibrary
     *
     * {talendTypes} String | String
     *
     * {Category} StringHandling
     *
     * {param} String value: String value
     *
     * {example} ENC(x1387yx=):secretpassword
     *
     */
    public static String decrypt (String message, String filepath) throws Exception {

    	//String encrypted = message.substring(4, message.length()-1);    	No Index out of bounds safe
    	/*
    	if (message.startsWith("ENC("))
    		System.out.println("We are decrypting " + message);
    	else
    		System.out.println("We are NOT decrypting " + message);
    	*/
    	initialize(filepath);
    	return message.startsWith("ENC(") ?  new String(encryptor.decrypt(DatatypeConverter.parseBase64Binary(message.replace(";", "=").substring(4, message.length()-1)))) : message;
 
    }
}
