import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Peticion extends Thread {
    private Socket socket;
    private PublicKey serverPublicKey;
    private PrivateKey serverPrivateKey;

    // Constructor que recibe el socket y las claves
    public Peticion(Socket socket, PublicKey serverPublicKey, PrivateKey serverPrivateKey) {
        this.socket = socket;
        this.serverPublicKey = serverPublicKey;
        this.serverPrivateKey = serverPrivateKey;
    }

    private void escuchar() {
        try {
            BufferedReader bf = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter pw = new PrintWriter(socket.getOutputStream(), true);

            // Recibir clave pública del cliente
            String clientPublicKeyString = bf.readLine();
            PublicKey clientPublicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(clientPublicKeyString)));

            // Imprimir información sobre la clave pública del cliente
            System.out.println("rutaPublicKey: clave_cliente.publica");
            System.out.println("clave publica cliente: " + clientPublicKey.toString());

            // Enviar clave pública del servidor al cliente
            pw.println(Base64.getEncoder().encodeToString(serverPublicKey.getEncoded()));

            String encryptedMessage;
            while ((encryptedMessage = bf.readLine()) != null) {
                String message = decrypt(Base64.getDecoder().decode(encryptedMessage));
                String[] parts = message.split(":", 2);
                String clientName = parts[0];
                String clientMessage = parts.length > 1 ? parts[1] : "";

                System.out.println("El cliente " + clientName + " dice: " + clientMessage);

                String response;
                switch (clientMessage) {
                    case "Buenos días":
                        response = "Buenos días " + clientName + ", ¿qué desea?";
                        break;
                    case "Buenas tardes":
                        response = "Buenas tardes " + clientName + ", ¿qué desea?";
                        break;
                    case "Buenas noches":
                        response = "Buenas noches " + clientName + ", ¿qué desea?";
                        break;
                    case "Deseo un menú Whopper":
                        response = clientName + ", aquí tiene su menú Whopper, ¿desea algo más?";
                        break;
                    case "Deseo un menú BigKing":
                        response = clientName + ", aquí tiene su menú BigKing, ¿desea algo más?";
                        break;
                    case "Deseo un menú LongChicken":
                        response = clientName + ", aquí tiene su menú LongChicken, ¿desea algo más?";
                        break;
                    case "Deseo un menú CrispyChicken":
                        response = clientName + ", aquí tiene su menú CrispyChicken, ¿desea algo más?";
                        break;
                    case "No quiero nada más":
                        response = "Gracias por su pedido";
                        break;
                    default:
                        response = "Perdona, no entendí.";
                }

                // Imprimir la respuesta antes de cifrarla
                System.out.println("Cadena original Servidor: " + response);

                byte[] encryptedResponse = encrypt(response, clientPublicKey);
                pw.println(Base64.getEncoder().encodeToString(encryptedResponse));
                
                // Imprimir el mensaje cifrado que se envía al cliente
                System.out.println("Mensaje cifrado servidor: " + Base64.getEncoder().encodeToString(encryptedResponse));
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

    private byte[] encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    private String decrypt(byte[] encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
        return new String(cipher.doFinal(encryptedMessage));
    }

    @Override
    public void run() {
        escuchar();
    }
}