import java.io.*;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.Cipher;

public class Peticion extends Thread {
    private Socket socket;
    private PublicKey publicKey; 
    private PrivateKey privateKey;
    private PublicKey clientPublicKey;

    public Peticion(Socket socket, PublicKey publicKey, PrivateKey privateKey) {
        this.socket = socket;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    @Override
    public void run() {
        try (BufferedReader bf = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter pw = new PrintWriter(socket.getOutputStream(), true)) {

            String clientPublicKeyString = bf.readLine();
            this.clientPublicKey = KeyUtil.stringToPublicKey(clientPublicKeyString);

            System.out.println("rutaPublicKey: clave_cliente.publica");
            System.out.println("Clave pública del cliente: " + clientPublicKey);

            pw.println(KeyUtil.publicKeyToString(publicKey));

            String encryptedMessage;
            while ((encryptedMessage = bf.readLine()) != null) {
                System.out.println("Mensaje cifrado recibido: " + encryptedMessage);
                String message = decrypt(encryptedMessage, privateKey);
                System.out.println("Mensaje descifrado: " + message);
                String[] parts = message.split(":", 2);
                String nombreCliente  = parts[0];
                String mensajeCliente;
                if (parts.length > 1) {
                    mensajeCliente = parts[1].trim();
                } else {
                    mensajeCliente = "";
                }

                System.out.println("El cliente " + nombreCliente + " dice: " + mensajeCliente);
                String respuesta = procesarMensaje(nombreCliente, mensajeCliente);
                double precio = obtenerPrecio(mensajeCliente);
                System.out.println("Cadena original Servidor: " + respuesta);
                String encryptedResponse = encrypt(respuesta, clientPublicKey);
                System.out.println("Mensaje cifrado servidor: " + encryptedResponse);
                pw.println(encryptedResponse);
                
                String encryptedPrice = encrypt(Double.toString(precio), clientPublicKey);
                pw.println(encryptedPrice);
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

    public String procesarMensaje(String clientName, String clientMessage) {
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

    public double obtenerPrecio(String mensajeCliente) {
        switch (mensajeCliente) {
            case "Deseo un menú Whopper":
                return 10.50;
            case "Deseo un menú BigKing":
                return 12.75;
            case "Deseo un menú LongChicken":
                return 9.95;
            case "Deseo un menú CrispyChicken":
                return 8.75;
            default:
                return 0.0;
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