import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.MessageDigest;

public class DiffieHellman {

    private static final String ALGORITMO_DH = "DH";

    // Generar un par de llaves Diffie-Hellman (pública y privada)
    public static KeyPair generarParLlaves() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITMO_DH);
        keyGen.initialize(1024); // Tamaño de 1024 bits
        return keyGen.generateKeyPair();
    }

    // Reconstruir una llave pública de Diffie-Hellman a partir de bytes
    public static PublicKey reconstruirLlavePublica(byte[] llavePublicaBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITMO_DH);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(llavePublicaBytes);
        return keyFactory.generatePublic(keySpec);
    }

    // Generar la llave secreta compartida usando tu llave privada y la llave pública del otro
    public static byte[] generarLlaveCompartida(PrivateKey llavePrivadaPropia, PublicKey llavePublicaOtro) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance(ALGORITMO_DH);
        ka.init(llavePrivadaPropia);
        ka.doPhase(llavePublicaOtro, true);
        return ka.generateSecret();
    }

    // Calcular el digest SHA-512 de la llave secreta compartida
    public static byte[] calcularDigestSHA512(byte[] llaveCompartida) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        return digest.digest(llaveCompartida);
    }
}
