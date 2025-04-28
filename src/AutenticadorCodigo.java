import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;

public class AutenticadorCodigo {

    //private static final String ALGORITMO_HMAC = "HmacSHA256";

    // Método para generar un código HMAC de un mensaje usando una llave secreta
    public static byte[] generarHMAC(SecretKey llaveSecreta, String algortimo, String mensaje) {
        byte [] codigoHMAC;
        try {
            Mac mac = Mac.getInstance(algortimo);
            mac.init(llaveSecreta);

            byte[] textoClaro = mensaje.getBytes(); //Datos
            codigoHMAC = mac.doFinal(textoClaro); 
            
            return codigoHMAC; 

        } catch (Exception e) {
            System.out.println("Excepción en generarHMAC: " + e.getMessage());
            return null;
        }
    }

    // Método para verificar si un HMAC es válido
    public static boolean verificarHMAC(SecretKey llaveSecreta, String algoritmo, String mensaje, byte[] hmacEsperado) {
        boolean resultado;
        try {
            Mac mac = Mac.getInstance(algoritmo);
            mac.init(llaveSecreta);
            
            byte[] datos = mensaje.getBytes();
            byte[] hmacCalculado = mac.doFinal(datos);

            resultado = compararHMAC(hmacEsperado, hmacCalculado); //Comparar HMAC calculado con el esperado

            return resultado;

        } catch (Exception e) {
            System.out.println("Excepción en verificarHMAC: " + e.getMessage());
            return false;

        }
    }

    // Método para reconstruir una llave HMAC a partir de bytes
    public static SecretKey reconstruirLlaveHMAC(byte[] llaveBytes, String algortimo) {
        return new SecretKeySpec(llaveBytes, algortimo);
    }
    private static boolean compararHMAC(byte[] hmacEsperado, byte[] hmacCalculado) {
        if (hmacEsperado.length != hmacCalculado.length) {
            return false;
        }

        for (int i = 0; i < hmacEsperado.length; i++) {
            if (hmacEsperado[i] != hmacCalculado[i]) {
                return false;
            }
        }

        return true;
    }
}
