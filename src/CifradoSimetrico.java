import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class CifradoSimetrico {

    private final static String PADDING = "AES/CBC/PKCS5Padding";
    private final static int AES_KEY_SIZE = 256;
    private final static int IV_SIZE = 16;

    // Método para cifrar texto plano usando una llave y un IV
    public static byte[] cifrar(SecretKey llave, IvParameterSpec iv, String mensaje) {
        byte[] mensajeCifrado;
        try {
            Cipher cifrador = Cipher.getInstance(PADDING);
            byte[] textoClaro = mensaje.getBytes();
            
            cifrador.init(Cipher.ENCRYPT_MODE, llave, iv);
            mensajeCifrado = cifrador.doFinal(textoClaro);

            return mensajeCifrado;

        } catch (Exception e) {
            System.out.println("Excepción en cifrar: " + e.getMessage());
            return null;
        }
    }

    // Método para descifrar un texto cifrado usando la misma llave y IV
    public static String descifrar(SecretKey llave, IvParameterSpec iv, byte[] mensajeCifrado) {
        byte[] mensajeDescifrado;
        try {
            Cipher cifrador = Cipher.getInstance(PADDING);
            cifrador.init(Cipher.DECRYPT_MODE, llave, iv);
            mensajeDescifrado = cifrador.doFinal(mensajeCifrado);

            return new String(mensajeDescifrado);

        } catch (Exception e) {
            System.out.println("Excepción en descifrar: " + e.getMessage());
            return null;
        }
    }

    // Método para generar una llave AES de 256 bits
    public static SecretKey generarLlaveAES() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);

        return keyGen.generateKey();
    }

    // Método para generar un IV aleatorio de 16 bytes
    public static IvParameterSpec generarIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        
        return new IvParameterSpec(iv);
    }

    // Método para reconstruir una llave AES desde un arreglo de bytes
    public static SecretKey reconstruirLlave(byte[] bytesLlave) {
        return new SecretKeySpec(bytesLlave, "AES");
    }
}
