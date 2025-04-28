

import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class DelegadoServidor implements Runnable {

    private Socket socketCliente;
    private PrivateKey llavePrivadaServidor;
    private PublicKey llavePublicaServidor;

    public DelegadoServidor(Socket socketCliente, PrivateKey llavePrivada, PublicKey llavePublica) {
        this.socketCliente = socketCliente;
        this.llavePrivadaServidor = llavePrivada;
        this.llavePublicaServidor = llavePublica;
    }

    @Override
    public void run() {
        try (
            ObjectOutputStream salida = new ObjectOutputStream(socketCliente.getOutputStream());
            ObjectInputStream entrada = new ObjectInputStream(socketCliente.getInputStream());
        ) {
            System.out.println("[DelegadoServidor] Atendiendo cliente: " + socketCliente.getInetAddress());

            // 1. HANDSHAKE: Intercambiar llaves Diffie-Hellman
            // -----------------------------------------------------
            // 1.1 Generar par de llaves Diffie-Hellman propias
            var parLlavesDH = DiffieHellman.generarParLlaves();
            var llavePrivadaDH = parLlavesDH.getPrivate();
            var llavePublicaDH = parLlavesDH.getPublic();

            // 1.2 Enviar llave pública DH al cliente
            salida.writeObject(llavePublicaDH.getEncoded());
            salida.flush();

            // 1.3 Recibir llave pública DH del cliente
            byte[] bytesLlavePublicaCliente = (byte[]) entrada.readObject();
            PublicKey llavePublicaClienteDH = DiffieHellman.reconstruirLlavePublica(bytesLlavePublicaCliente);

            // 1.4 Generar la llave secreta compartida
            byte[] llaveCompartida = DiffieHellman.generarLlaveCompartida(llavePrivadaDH, llavePublicaClienteDH);

            // 1.5 Calcular digest SHA-512 de la llave compartida
            byte[] digestLlave = DiffieHellman.calcularDigestSHA512(llaveCompartida);

            // 1.6 Separar digest en dos llaves:
            byte[] bytesLlaveAES = new byte[32];
            byte[] bytesLlaveHMAC = new byte[32];
            System.arraycopy(digestLlave, 0, bytesLlaveAES, 0, 32);
            System.arraycopy(digestLlave, 32, bytesLlaveHMAC, 0, 32);

            SecretKey llaveAES = CifradoSimetrico.reconstruirLlave(bytesLlaveAES);
            SecretKey llaveHMAC = AutenticadorCodigo.reconstruirLlaveHMAC(bytesLlaveHMAC);

            System.out.println("[DelegadoServidor] Llaves de sesión generadas exitosamente.");

            // ---- Aquí después pondremos: 
            // - Cifrar la tabla de servicios,
            // - Firmarla,
            // - Enviar,
            // - Validar HMACs, 
            // - Atender consultas.

        } catch (Exception e) {
            System.out.println("[DelegadoServidor] Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
