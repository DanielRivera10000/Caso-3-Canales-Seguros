
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ServidorPrincipal {

    private static final int PUERTO = 12345; // Puerto donde escucha el servidor
    private static final String RUTA_LLAE_PRIVADA = "keys/private.key";
    private static final String RUTA_LLAE_PUBLICA = "keys/public.key";

    private PrivateKey llavePrivada;
    private PublicKey llavePublica;

    public ServidorPrincipal() throws Exception {
        inicializarLlavesRSA();
    }

    // Inicializa las llaves RSA del servidor (genera si no existen)
    private void inicializarLlavesRSA() throws Exception {
        if (Files.exists(Paths.get(RUTA_LLAE_PRIVADA)) && Files.exists(Paths.get(RUTA_LLAE_PUBLICA))) {
            // Leer las llaves desde archivo
            byte[] bytesPrivada = Files.readAllBytes(Paths.get(RUTA_LLAE_PRIVADA));
            byte[] bytesPublica = Files.readAllBytes(Paths.get(RUTA_LLAE_PUBLICA));
            llavePrivada = (PrivateKey) Utilidades.deserializarObjeto(bytesPrivada);
            llavePublica = (PublicKey) Utilidades.deserializarObjeto(bytesPublica);
        } else {
            // Generar nuevas llaves y guardarlas
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.generateKeyPair();
            llavePrivada = keyPair.getPrivate();
            llavePublica = keyPair.getPublic();

            // Guardar las llaves
            Utilidades.serializarObjeto(llavePrivada, RUTA_LLAE_PRIVADA);
            Utilidades.serializarObjeto(llavePublica, RUTA_LLAE_PUBLICA);
        }
    }

    // Método principal: escuchar y aceptar clientes
    public void iniciarServidor() {
        try (ServerSocket serverSocket = new ServerSocket(PUERTO)) {
            System.out.println("Servidor Principal escuchando en el puerto " + PUERTO);

            while (true) {
                Socket socketCliente = serverSocket.accept();
                System.out.println("Cliente conectado desde: " + socketCliente.getInetAddress());

                // Crear un delegado para atender a este cliente
                DelegadoServidor delegado = new DelegadoServidor(socketCliente, llavePrivada, llavePublica);
                Thread hiloDelegado = new Thread(delegado);
                hiloDelegado.start(); // Atiende concurrentemente
            }
        } catch (Exception e) {
            System.out.println("Error en el servidor: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        try {
            ServidorPrincipal servidor = new ServidorPrincipal();
            servidor.iniciarServidor();
        } catch (Exception e) {
            System.out.println("Error iniciando el servidor: " + e.getMessage());
        }
    }
}
