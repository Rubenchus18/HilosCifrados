import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;

public class ClienteBurger {
    static Scanner reader = new Scanner(System.in);
    
    private String nombreCliente;
    private int edad;
    private double saldo;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public ClienteBurger(String nombreCliente, int edad, double saldo) throws Exception {
        this.nombreCliente = nombreCliente;
        this.edad = edad;
        this.saldo = saldo;
        generateKeyPair(); // Generar par de claves
    }

    private void generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Tamaño de la clave
        KeyPair pair = keyGen.generateKeyPair();
        this.publicKey = pair.getPublic(); // Clave pública
        this.privateKey = pair.getPrivate(); // Clave privada

        // Imprimir claves en consola
        System.out.println("Clave pública del cliente: " + Base64.getEncoder().encodeToString(this.publicKey.getEncoded()));
        System.out.println("Clave privada del cliente: " + Base64.getEncoder().encodeToString(this.privateKey.getEncoded()));
    }

    public void comprar() throws Exception {
        Socket socket = null;
        BufferedReader bfr = null;
        PrintWriter pw = null;
        InputStreamReader isr = null;

        try {
            InetSocketAddress direccion = new InetSocketAddress("localhost", 9876);

            if (this.edad >= 18) {
                socket = new Socket();
                socket.connect(direccion);

                pw = new PrintWriter(socket.getOutputStream(), true);
                pw.println(Base64.getEncoder().encodeToString(this.publicKey.getEncoded()));

                isr = new InputStreamReader(socket.getInputStream());
                bfr = new BufferedReader(isr);
                String serverPublicKeyString = bfr.readLine();
                PublicKey serverPublicKey = KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(serverPublicKeyString)));

                System.out.println("Ruta de la clave pública del servidor: clave_servidor.publica");

                String mensaje;
                while (true) {
                    System.out.print(this.nombreCliente + ": ");
                    mensaje = reader.nextLine();

                    // Cifrar mensaje con la clave pública del servidor
                    byte[] encryptedMessage = encrypt(mensaje, serverPublicKey);
                    String encryptedMessageString = Base64.getEncoder().encodeToString(encryptedMessage);
                    
                    // Imprimir el mensaje original y el mensaje cifrado en consola
                    System.out.println("Cadena original: " + mensaje);
                    System.out.println("Mensaje cifrado: " + encryptedMessageString);
                    
                    pw.println(encryptedMessageString);

                    String encryptedResponse = bfr.readLine();
                    if (encryptedResponse != null) { 
                        String response = decrypt(Base64.getDecoder().decode(encryptedResponse));
                        System.out.println("Dependiente: " + response);
                        if (response.equals("Gracias por su pedido")) {
                            System.out.println("El cliente " + this.nombreCliente + " ha terminado su pedido.");
                            break; 
                        }
                    } else {
                        System.out.println("No se recibió respuesta del servidor.");
                    }
                }
            } else {
                System.out.println("Dependiente: Usted no puede comprar, es menor de edad " + this.nombreCliente);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            close(pw);
            close(bfr);
            close(isr);
            close(socket);
        }
    }

    private byte[] encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    private String decrypt(byte[] encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey); // Desencriptar con la clave privada del cliente
        return new String(cipher.doFinal(encryptedMessage));
    }

    private void close(Socket socket) {
        try {
            if (null != socket) {
                socket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void close(PrintWriter writer) throws IOException {
        if (null != writer) {
		    writer.close();
		}
    }

    private void close(BufferedReader reader) {
        try {
            if (null != reader) {
                reader.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void close(InputStreamReader reader) {
        try {
            if (null != reader) {
                reader.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            ClienteBurger cliente = new ClienteBurger("Ruben", 23, 50);
            cliente.comprar();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}