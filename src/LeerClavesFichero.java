
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class LeerClavesFichero {
	
	KeyFactory keyRSA;
	public LeerClavesFichero() throws NoSuchAlgorithmException { 
		keyRSA = KeyFactory.getInstance("RSA");
	}

	public PublicKey readOfFilePublicKey(String fileName) throws IOException, InvalidKeySpecException {
		PublicKey publicKey=null;
		FileInputStream inpub = null;
		
		try {
			// Leer del fichero binario la clave publica
			inpub = new FileInputStream(fileName);
			byte[] bufferPub = new byte[inpub.available()];
			inpub.read(bufferPub);
			
			// Recupera la clave publica codificada en formato X509
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bufferPub);
			publicKey = keyRSA.generatePublic(keySpec);			
		}
		catch(IOException | InvalidKeySpecException e) {
			e.printStackTrace();
			throw e;
		}
		finally {
			if (null != inpub) {
				inpub.close();
			}
		}
		
		return publicKey;
	}
	
	public PrivateKey readOfFilePrivateKey(String fileName) throws IOException, InvalidKeySpecException {
		PrivateKey privateKey=null;
		FileInputStream inpub = null;
		
		try {
			// Leer del fichero binario la clave privada
			inpub = new FileInputStream(fileName);
			byte[] bufferPriv = new byte[inpub.available()];
			inpub.read(bufferPriv);
			
			// Recupera la clave privada codificada en formato PKCS8
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bufferPriv);
			privateKey = keyRSA.generatePrivate(keySpec);			
		}
		catch(IOException | InvalidKeySpecException e) {
			e.printStackTrace();
			throw e;
		}
		finally {
			if (null != inpub) {
				inpub.close();
			}
		}
		
		return privateKey;
	}

	public static void main(String[] args) throws Exception {
		// Leer de disco las claves publica y privada
		LeerClavesFichero leer = new LeerClavesFichero();
		PrivateKey privateKey = leer.readOfFilePrivateKey("clave.privada");
		System.out.println("Clave privada: "+privateKey.toString());
		
		PublicKey publicKey = leer.readOfFilePublicKey("clave.publica");
		System.out.println("Clave publica: "+publicKey.toString());
	}

}
