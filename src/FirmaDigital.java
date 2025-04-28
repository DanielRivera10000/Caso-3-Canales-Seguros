import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class FirmaDigital {

    //private static final String ALGORITMO_FIRMA = "SHA256withRSA";

    // Método para firmar un texto (String) usando una llave privada
    public static byte[] firmar(PrivateKey llavePrivada, String algoritmo, String mensaje) {
        try {
            Signature firma = Signature.getInstance(algoritmo);
            firma.initSign(llavePrivada);
            firma.update(mensaje.getBytes());

            byte[] firmarTexto = firma.sign();
            return firmarTexto;

        } catch (Exception e) {
            System.out.println("Excepción en firmarTexto: " + e.getMessage());
            return null;
        }
    }

    // Método para verificar una firma usando una llave pública
    public static boolean verificar(PublicKey llavePublica, String mensaje, byte[] firmaTextoBytes, String algoritmo) {
        boolean verificarTexto;
        try {
            Signature verificador = Signature.getInstance(algoritmo);
            verificador.initVerify(llavePublica);
            verificador.update(mensaje.getBytes());
            verificarTexto = verificador.verify(firmaTextoBytes);

            return verificarTexto;

        } catch (Exception e) {
            System.out.println("Excepción en verificarFirma: " + e.getMessage());
            return false;
        }
    }
}
