import java.io.*;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

public class Peticion extends Thread {
    private Socket socket;
    private PublicKey publicKey; // Clave pública del servidor
    private PrivateKey privateKey; // Clave privada del servidor
    private PublicKey clientPublicKey; // Clave pública del cliente

    public Peticion(Socket socket, PublicKey publicKey, PrivateKey privateKey) {
        this.socket = socket;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    @Override
    public void run() {
        try (BufferedReader bf = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter pw = new PrintWriter(socket.getOutputStream(), true)) {

            // 1. Recibir la clave pública del cliente
            String clientPublicKeyString = bf.readLine();
            this.clientPublicKey = KeyUtil.stringToPublicKey(clientPublicKeyString);

            // Mostrar clave pública del cliente
            System.out.println("rutaPublicKey: clave_cliente.publica");
            System.out.println("Clave pública del cliente: " + clientPublicKey);

            // 2. Enviar la clave pública del servidor al cliente
            pw.println(KeyUtil.publicKeyToString(publicKey));

            String encryptedMessage;
            while ((encryptedMessage = bf.readLine()) != null) {
                // Mostrar mensaje cifrado recibido
                System.out.println("Mensaje cifrado recibido: " + encryptedMessage);

                // 3. Descifrar el mensaje recibido con la clave privada del servidor
                String message = decrypt(encryptedMessage, privateKey);

                // Mostrar mensaje descifrado
                System.out.println("Mensaje descifrado: " + message);

                String[] parts = message.split(":", 2);
                String clientName = parts[0];
                String clientMessage = parts.length > 1 ? parts[1].trim() : "";

                System.out.println("El cliente " + clientName + " dice: " + clientMessage);

                // 4. Procesar el mensaje y generar una respuesta
                String response = procesarMensaje(clientName, clientMessage);

                // Mostrar cadena original del servidor
                System.out.println("Cadena original Servidor: " + response);

                // 5. Cifrar la respuesta con la clave pública del cliente
                String encryptedResponse = encrypt(response, clientPublicKey);

                // Mostrar mensaje cifrado que se envía al cliente
                System.out.println("Mensaje cifrado servidor: " + encryptedResponse);

                // Enviar respuesta cifrada al cliente
                pw.println(encryptedResponse);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    // Método para procesar el mensaje y generar una respuesta
    private String procesarMensaje(String clientName, String clientMessage) {
        switch (clientMessage) {
            case "Buenos días":
                return "Buenos días " + clientName + ", ¿qué desea?";
            case "Buenas tardes":
                return "Buenas tardes " + clientName + ", ¿qué desea?";
            case "Buenas noches":
                return "Buenas noches " + clientName + ", ¿qué desea?";
            case "Deseo un menú Whopper":
                return clientName + ", aquí tiene su menú Whopper, ¿desea algo más?";
            case "Deseo un menú BigKing":
                return clientName + ", aquí tiene su menú BigKing, ¿desea algo más?";
            case "Deseo un menú LongChicken":
                return clientName + ", aquí tiene su menú LongChicken, ¿desea algo más?";
            case "Deseo un menú CrispyChicken":
                return clientName + ", aquí tiene su menú CrispyChicken, ¿desea algo más?";
            case "No quiero nada más":
                return "Gracias por su pedido";
            default:
                return "Perdona, no entendí.";
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