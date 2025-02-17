import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ServidorBurger {
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public ServidorBurger() throws Exception {
        // Leer claves desde archivos
        LeerClavesFichero leerClaves = new LeerClavesFichero();
        this.privateKey = leerClaves.readOfFilePrivateKey("clave_servidor.privada");
        this.publicKey = leerClaves.readOfFilePublicKey("clave_servidor.publica");
    }

    public void iniciarServidor() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(9876)) {
            System.out.println("Tienda abierta");

            while (true) {
                try {
                    Socket socket = serverSocket.accept();
                    System.out.println("Conexion recibida!");

                    // Crear un nuevo hilo para manejar la petición
                    Peticion peticion = new Peticion(socket, publicKey, privateKey);
                    peticion.start();
                } catch (IOException e) {
                    System.out.println("Error al aceptar la conexión: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.out.println("Error al iniciar el servidor: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        try {
            ServidorBurger servidor = new ServidorBurger();
            servidor.iniciarServidor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}