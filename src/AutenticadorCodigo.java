import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;

public class AutenticadorCodigo {

    private static final String ALGORITMO_HMAC = "HmacSHA256";

    // Método para generar un código HMAC de un mensaje usando una llave secreta
    public static byte[] generarHMAC(SecretKey llave, String mensaje) {
        try {
            Mac mac = Mac.getInstance(ALGORITMO_HMAC);
            mac.init(llave);
            return mac.doFinal(mensaje.getBytes());
        } catch (Exception e) {
            System.out.println("Excepción en generarHMAC: " + e.getMessage());
            return null;
        }
    }

    // Método para verificar si un HMAC es válido
    public static boolean verificarHMAC(SecretKey llave, String mensaje, byte[] hmacEsperado) {
        try {
            Mac mac = Mac.getInstance(ALGORITMO_HMAC);
            mac.init(llave);
            byte[] hmacCalculado = mac.doFinal(mensaje.getBytes());

            // Comparar byte a byte
            if (hmacCalculado.length != hmacEsperado.length) return false;
            for (int i = 0; i < hmacCalculado.length; i++) {
                if (hmacCalculado[i] != hmacEsperado[i]) return false;
            }
            return true;
        } catch (Exception e) {
            System.out.println("Excepción en verificarHMAC: " + e.getMessage());
            return false;
        }
    }

    // Método para reconstruir una llave HMAC a partir de bytes
    public static SecretKey reconstruirLlaveHMAC(byte[] bytesLlave) {
        return new SecretKeySpec(bytesLlave, ALGORITMO_HMAC);
    }
}
