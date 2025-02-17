
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.NoSuchPaddingException;

public class AlmacenarClavesFichero {
	
	KeyPair claves;//Clave publica y privada
	KeyPairGenerator generadorClaves;
	
	public AlmacenarClavesFichero() throws NoSuchAlgorithmException, NoSuchPaddingException {
		//Generador de claves: RSA
		generadorClaves = KeyPairGenerator.getInstance("RSA");
		//Usaremos una longitud de clave de 2048 bits
		generadorClaves.initialize(2048);
		//Generamos la clave publica y privada
		claves = generadorClaves.generateKeyPair();
	}

	public PublicKey getPublica() {
		return claves.getPublic();
	}

	public PrivateKey getPrivada() {
		return claves.getPrivate();
	}
	
	public void saveToFilePrivateKey(PrivateKey privateKey, String fileName) throws IOException {
		FileOutputStream outpriv = null;
		try {
			//Para almacenar la clave privada en disco es necesario codificarla en formato PKCS8
			PKCS8EncodedKeySpec pk8Spec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
			
			//Escribir a fichero binario la clave privada
			outpriv = new FileOutputStream(fileName);
			outpriv.write(pk8Spec.getEncoded());
		}
		catch(IOException e) {
			e.printStackTrace();
			throw e;
		}
		finally {
			if (null != outpriv) {
				outpriv.close();
			}
		}		
	}
	
	public void saveToFilePublicKey(PublicKey publicKey, String fileName) throws IOException {
		FileOutputStream outpub = null;
		try {
			//Para almacenar la clave publica en disco es necesario codificarla en formato X509
			X509EncodedKeySpec pkX509 = new X509EncodedKeySpec(publicKey.getEncoded());
			
			//Escribir a fichero binario la clave publica
			outpub = new FileOutputStream(fileName);
			outpub.write(pkX509.getEncoded());
		}
		catch(IOException e) {
			e.printStackTrace();
			throw e;
		}
		finally {
			if (null != outpub) {
				outpub.close();
			}
		}		
	}

	public static void main(String[] args) throws Exception {
		// Almacenar en disco las claves publica y privada
		AlmacenarClavesFichero almacenar = new AlmacenarClavesFichero();
		almacenar.saveToFilePrivateKey(almacenar.getPrivada(), "clave.privada");
		almacenar.saveToFilePublicKey(almacenar.getPublica(), "clave.publica");
	}

}
