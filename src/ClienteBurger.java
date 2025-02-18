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
    private PublicKey publicKey; 
    private PrivateKey privateKey; 
    private PublicKey serverPublicKey; 

    public ClienteBurger(String nombreCliente, int edad, double saldo) throws Exception {
   
            this.nombreCliente = nombreCliente;
            this.edad = edad;
            this.saldo = saldo;

         
        
    }
    public void comprar() throws Exception {
        if (this.edad<18) {
            System.out.println(nombreCliente+"no se puede conectar al servidor porque no se generaron las claves necesarias.");
            return;
        }else {
        	   KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
               keyGen.initialize(2048);
               KeyPair pair = keyGen.generateKeyPair();
               this.publicKey = pair.getPublic();
               this.privateKey = pair.getPrivate();

               System.out.println("Clave pública del cliente: " + KeyUtil.publicKeyToString(publicKey));
               System.out.println("Clave privada del cliente: " + KeyUtil.privateKeyToString(privateKey));
               try (Socket socket = new Socket()) {
                   socket.connect(new InetSocketAddress("localhost", 9876));

                   try (PrintWriter pw = new PrintWriter(socket.getOutputStream(), true);
                        BufferedReader bf = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

                       pw.println(KeyUtil.publicKeyToString(publicKey));

                       String serverPublicKeyString = bf.readLine();
                       this.serverPublicKey = KeyUtil.stringToPublicKey(serverPublicKeyString);

                       System.out.println("Clave pública del servidor recibida: " + serverPublicKeyString);

                       Scanner reader = new Scanner(System.in);
                       String resultado = "";

                       while (!resultado.equals("Gracias por su pedido") && saldo > 0) {
                           System.out.print(nombreCliente + ": ");
                           String mensaje = reader.nextLine();
                           System.out.println("Cadena original: " + mensaje);
                           String encryptedMessage = encrypt(nombreCliente + ":" + mensaje, serverPublicKey);
                           System.out.println("Mensaje cifrado: " + encryptedMessage);
                           pw.println(encryptedMessage);              
                           String encryptedResponse = bf.readLine();
                           System.out.println("Cadena recibida del servidor: " + encryptedResponse);
                           resultado = decrypt(encryptedResponse, privateKey);
                           System.out.println("Dependiente: " + resultado);

                           String encryptedPrice = bf.readLine();
                           String priceString = decrypt(encryptedPrice, privateKey);
                           double precio = Double.parseDouble(priceString);
                           System.out.println("Precio del pedido: " + precio);

                  
                           saldo=saldo-precio;
                           System.out.println("Saldo restante: " + saldo);

                           if (saldo <= 0) {
                               System.out.println("Saldo insuficiente.Hasta luego.");
                               break;
                           }
                       }
                   }
               }
        }

        
    }
    public String encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes);
    }
}