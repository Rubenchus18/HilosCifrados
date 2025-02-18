import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ServidorBurger {
    private static final long MAX_TIME = 3 * 60 * 1000; 
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public ServidorBurger() throws Exception {
     
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        this.publicKey = pair.getPublic();
        this.privateKey = pair.getPrivate();
    }

    public void iniciarServidor() throws Exception {
        ServerSocket socketEscucha = null;
        try {
            socketEscucha = new ServerSocket(9876);
            System.out.println("Auto King abierto");

            final long INIT_TIME = System.currentTimeMillis();
            while (System.currentTimeMillis() <= (INIT_TIME + MAX_TIME)) {
                Socket conexion = socketEscucha.accept();
                Peticion hilo = new Peticion(conexion, publicKey, privateKey);
                hilo.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (socketEscucha != null) {
                socketEscucha.close();
            }
        }
    }

    public static void main(String[] args) throws Exception {
        ServidorBurger servidor = new ServidorBurger();
        servidor.iniciarServidor();
    }
}