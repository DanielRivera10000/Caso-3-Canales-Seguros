import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class DiffieHellman {

    private static final String algoritmo = "DH";

    // Generar un par de llaves Diffie-Hellman (pública y privada)
    public static KeyPair generarParLlaves() {
        try {
            KeyPairGenerator generadorLlave = KeyPairGenerator.getInstance(algoritmo);
            generadorLlave.initialize(1024); // Tamaño de 1024 bits
            
            return generadorLlave.generateKeyPair();

        } catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }
    }


    // Reconstruir una llave pública de Diffie-Hellman a partir de bytes
    public static PublicKey reconstruirLlavePublica(byte[] llavePublica) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(algoritmo);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(llavePublica);//EN BYTES
        
            return keyFactory.generatePublic(keySpec);

        } catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }
    }

    // Generar la llave secreta compartida usando tu llave privada y la llave pública del otro
    public static byte[] generarLlaveCompartida(PrivateKey llavePrivadaPropia, PublicKey llavePublicaOtro) {
        try {
            KeyAgreement acuerdo = KeyAgreement.getInstance(algoritmo);
            acuerdo.init(llavePrivadaPropia);
            acuerdo.doPhase(llavePublicaOtro, true);
            
            return acuerdo.generateSecret();

        } catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }
    }

    // Calcular el digest SHA-512 de la llave secreta compartida
    public static byte[] calcularDigestSHA512(byte[] llaveCompartida) {
        try {
            MessageDigest mensaje = MessageDigest.getInstance("SHA-512");
            
            return mensaje.digest(llaveCompartida);
        
        } catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }   
    }
}
