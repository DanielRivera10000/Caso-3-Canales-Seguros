import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class FirmaDigital {

    private static final String ALGORITMO_FIRMA = "SHA256withRSA";

    // Método para firmar un texto (String) usando una llave privada
    public static byte[] firmarTexto(PrivateKey llavePrivada, String mensaje) {
        try {
            Signature firma = Signature.getInstance(ALGORITMO_FIRMA);
            firma.initSign(llavePrivada);
            firma.update(mensaje.getBytes());
            return firma.sign();
        } catch (Exception e) {
            System.out.println("Excepción en firmarTexto: " + e.getMessage());
            return null;
        }
    }

    // Método para verificar una firma usando una llave pública
    public static boolean verificarFirma(PublicKey llavePublica, String mensaje, byte[] firmaBytes) {
        try {
            Signature verificador = Signature.getInstance(ALGORITMO_FIRMA);
            verificador.initVerify(llavePublica);
            verificador.update(mensaje.getBytes());
            return verificador.verify(firmaBytes);
        } catch (Exception e) {
            System.out.println("Excepción en verificarFirma: " + e.getMessage());
            return false;
        }
    }
}
