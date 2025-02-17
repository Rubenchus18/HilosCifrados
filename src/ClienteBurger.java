import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;

public class ClienteBurger {
    private String nombreCliente;
    private int edad;
    private double saldo;
    private PublicKey publicKey; // Clave pública del cliente
    private PrivateKey privateKey; // Clave privada del cliente
    private PublicKey serverPublicKey; // Clave pública del servidor

    public ClienteBurger(String nombreCliente, int edad, double saldo) throws Exception {
        this.nombreCliente = nombreCliente;
        this.edad = edad;
        this.saldo = saldo;

        // Generar par de claves RSA para el cliente
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        this.publicKey = pair.getPublic();
        this.privateKey = pair.getPrivate();

        // Mostrar claves generadas
        System.out.println("Clave pública del cliente: " + KeyUtil.publicKeyToString(publicKey));
        System.out.println("Clave privada del cliente: " + KeyUtil.privateKeyToString(privateKey));
    }

    public void comprar() throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("localhost", 9876));

            try (PrintWriter pw = new PrintWriter(socket.getOutputStream(), true);
                 BufferedReader bf = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

                // 1. Enviar la clave pública del cliente al servidor
                pw.println(KeyUtil.publicKeyToString(publicKey));

                // 2. Recibir la clave pública del servidor
                String serverPublicKeyString = bf.readLine();
                this.serverPublicKey = KeyUtil.stringToPublicKey(serverPublicKeyString);

                // Mostrar clave pública del servidor
                System.out.println("Clave pública del servidor recibida: " + serverPublicKeyString);

                Scanner reader = new Scanner(System.in);
                String resultado = "";

                while (!resultado.equals("Gracias por su pedido")) {
                    System.out.print(nombreCliente + ": ");
                    String mensaje = reader.nextLine();

                    // Mostrar cadena original
                    System.out.println("Cadena original: " + mensaje);

                    // 3. Cifrar el mensaje con la clave pública del servidor
                    String encryptedMessage = encrypt(nombreCliente + ":" + mensaje, serverPublicKey);

                    // Mostrar mensaje cifrado
                    System.out.println("Mensaje cifrado: " + encryptedMessage);

                    // Enviar mensaje cifrado al servidor
                    pw.println(encryptedMessage);

                    // 4. Recibir respuesta cifrada del servidor
                    String encryptedResponse = bf.readLine();

                    // Mostrar mensaje cifrado recibido
                    System.out.println("Cadena recibida del servidor: " + encryptedResponse);

                    // 5. Descifrar la respuesta con la clave privada del cliente
                    resultado = decrypt(encryptedResponse, privateKey);

                    // Mostrar respuesta descifrada
                    System.out.println("Dependiente: " + resultado);
                }
            }
        }
    }

    // Método para cifrar un mensaje con una clave pública
    private String encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Método para descifrar un mensaje con una clave privada
    private String decrypt(String encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes);
    }
}