import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.Key;
import java.util.Scanner;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import Decoder.BASE64Decoder;
import Decoder.BASE64Encoder;

public class AESEncryptionDecryptionTest {

  private static final String ALGORITHM       = "AES";
  private static final String myEncryptionKey = "ThisIsFoundation";
  private static final String UNICODE_FORMAT  = "UTF8";
  //static Logger loggger = Logger.getLogger(AESEncryptionDecryptionTest.class.getName());

  public static String encrypt(String valueToEnc) throws Exception {
     Key key = generateKey();
     Cipher c = Cipher.getInstance(ALGORITHM);
     c.init(Cipher.ENCRYPT_MODE, key);  
     byte[] encValue = c.doFinal(valueToEnc.getBytes());
     String encryptedValue = new BASE64Encoder().encode(encValue);
     return encryptedValue;
  }

public static String decrypt(String encryptedValue) throws Exception {
    Key key = generateKey();
    Cipher c = Cipher.getInstance(ALGORITHM);
    c.init(Cipher.DECRYPT_MODE, key);
    byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedValue);
    byte[] decValue = c.doFinal(decordedValue);//////////LINE 50
    String decryptedValue = new String(decValue);
    return decryptedValue;
}

private static Key generateKey() throws Exception {
    byte[] keyAsBytes;
    keyAsBytes = myEncryptionKey.getBytes(UNICODE_FORMAT);
    Key key = new SecretKeySpec(keyAsBytes, ALGORITHM);
    return key;
}

public static void main(String[] args) throws Exception {
	
	File path=null;
	String contents=null;
	String valueEnc,valueDec=null;
	OutputStream om=null;
	int stInput;
	try{
		System.out.println("En-Decryptor");
		Scanner in=new Scanner(System.in);
		System.out.println("Enter File Path in the Following Format: D:/Ashu/Ashu/ib.txt");

	    String filepath = in.nextLine();
	    File checkFile=new File(filepath);
	    if(checkFile.isFile()&&checkFile.exists()){
		System.out.println("----------------------");
		System.out.println("En/Decrypt Your Text File");
		System.out.println("1. Encrypt");
		System.out.println("2. Decrypt");
		System.out.println("3. ShutDown This Machine");
		System.out.println("4. ShutDown This Machine");
		System.out.println("----------------------");
		
		do{
		stInput=in.nextInt();
	switch(stInput)
	{
	case 1: path=new File(filepath);
			try {
					contents = new Scanner(path).useDelimiter("\\Z").next();
				} catch (FileNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			valueEnc = AESEncryptionDecryptionTest.encrypt(contents);
			om=new FileOutputStream(filepath);
			om.write(valueEnc.getBytes());
			//path.delete();
			System.out.println("Encrypted");
			break;
			
	case 2: path=new File(filepath);
			try {
				contents = new Scanner(path).useDelimiter("\\Z").next();
			} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
				e.printStackTrace();
			}
			valueDec = AESEncryptionDecryptionTest.decrypt(contents);
			om=new FileOutputStream(filepath);
			om.write(valueDec.getBytes());
			//path.delete();
			System.out.println("Decrypted");
			break;
	case 3:Runtime runtime = Runtime.getRuntime();
    	   Process proc = runtime.exec("shutdown -s -t 0");
    	   System.exit(0);
    	   break;
	case 4: System.out.println("Quitting");
			break;
			
	default: System.out.println("Not a valid Input");
	}
	}while(stInput!=3);
	    }
	    else{
	    	System.out.println("Not a valid Input");
	    }
	}
	catch(Exception e)
	{
		e.printStackTrace();
	}
	finally
	{
		path=null;
		contents=null;
		valueDec=null;
		valueEnc=null;
		/*om.flush();
		om.close();*/
	}
	}

}