import java.security.Key;

import javax.crypto.Cipher;

public class CifradoAsimetrico {

    public static byte[] cifrar(Key llavePublica, String algoritmo, String mensaje) {
        byte[] mensajeCifrado;
        try {
            Cipher cifrador = Cipher.getInstance(algoritmo);
            cifrador.init(Cipher.ENCRYPT_MODE, llavePublica);

            byte[] textoClaro = mensaje.getBytes();
            mensajeCifrado = cifrador.doFinal(textoClaro);

            return mensajeCifrado;

        } catch (Exception e) {
            System.out.println("Error al cifrar el texto: " + e.getMessage());
            return null;
        }
    }

    public static byte[] descifrar(Key llavePrivada, String algoritmo, byte[] mensajeCifrado) {
        byte[] mensajeDecifrado;
        try {
            Cipher cifrador = Cipher.getInstance(algoritmo);
            cifrador.init(Cipher.DECRYPT_MODE, llavePrivada);

            mensajeDecifrado = cifrador.doFinal(mensajeCifrado);
            return mensajeDecifrado;
            
        } catch (Exception e) {
            System.out.println("Error al descifrar el texto: " + e.getMessage());
            return null;
        }
        
    }

}
