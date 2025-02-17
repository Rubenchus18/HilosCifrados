
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class GestorCifrado {
	KeyPair claves; // Clave publica y privada
	KeyPairGenerator generadorClaves;
	Cipher cifrador;

	public GestorCifrado() throws NoSuchAlgorithmException, NoSuchPaddingException {
		//Generador de claves: RSA
		generadorClaves = KeyPairGenerator.getInstance("RSA");
		/*
		 * Usaremos una longitud de clave de 1024 bits
		 */
		generadorClaves.initialize(1024);
		//Generamos la clave publica y privada
		claves = generadorClaves.generateKeyPair();
		cifrador = Cipher.getInstance("RSA");
	}

	public PublicKey getPublica() {
		return claves.getPublic();
	}

	public PrivateKey getPrivada() {
		return claves.getPrivate();
	}

	/**
	 * Encripta los datos con la clave de cifrado aportada
	 * @param paraCifrar
	 * @param claveCifrado
	 * @return byte[]
	 * 
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] cifrar(byte[] paraCifrar, PublicKey claveCifrado) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		// Se pone el cifrador en modo cifrado, y se le pasa la clave para encriptar
		cifrador.init(Cipher.ENCRYPT_MODE, claveCifrado);
		//Encripta los datos
		byte[] resultado = cifrador.doFinal(paraCifrar);
		return resultado;
	}

	/**
	 * Desencripta los datos con la clve de descrifrado aportada
	 * @param paraDescifrar
	 * @param claveDescifrado
	 * @return byte[]
	 * 
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] descifrar(byte[] paraDescifrar, Key claveDescifrado)
			throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		// Se pone el cifrador en modo descifrado
		cifrador.init(Cipher.DECRYPT_MODE, claveDescifrado);
		// Desencriptamos
		byte[] resultado = cifrador.doFinal(paraDescifrar);
		return resultado;
	}

	public static void main(String[] args) throws Exception {
		
		try {
			GestorCifrado gestorCifrado = new GestorCifrado();
			PublicKey clavePublica = gestorCifrado.getPublica();
			//Los objetos que cifran y descifran en Java utilizan estrictamente objetos byte[]
			String mensajeOriginal = "Hola mundo";
			byte[] mensajeCifrado = gestorCifrado.cifrar(mensajeOriginal.getBytes(), clavePublica);
			//Convertimos a String para poder visulaizar los resultados
			String cadCifrada = new String(mensajeCifrado, "UTF-8");
	
			System.out.println("Cadena original:" + mensajeOriginal);
			System.out.println("Cadena cifrada:" + cadCifrada);
	
			/*
			 * Cogemos la cadCifrada y la desciframos con la otra clave
			 */
			PrivateKey clavePrivada = gestorCifrado.getPrivada();
			byte[] descifrada = gestorCifrado.descifrar(mensajeCifrado, clavePrivada);
			/* E imprimimos el mensaje */
			String mensajeDescifrado = new String(descifrada, "UTF-8");
			System.out.println("El mensaje descifrado es:" + mensajeDescifrado);
		}
		catch(InvalidKeyException | IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
			e.printStackTrace();
			throw e;
		}
			
	}
}

