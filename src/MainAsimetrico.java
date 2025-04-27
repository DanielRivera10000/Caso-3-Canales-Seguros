import java.security.*;
import java.util.Scanner;

public class MainAsimetrico {
    private final static String ALGORITMO = "RSA";
    public static void imprimir (byte[] contenido) {
        int i = 0;
        for (; i < contenido.length - 1; i++) {
            System.out.print(contenido[i] + " ");
        }
        System.out.println(contenido[i] + " ");
    }
    public static void main(String[] args) throws Exception {
        try{
            Scanner scanner = new Scanner(System.in);
            // Inputs:
            System.out.println("Escriba el mensaje de texto: ");
            String textoOriginal = scanner.nextLine();
            System.out.println(" Input en texto plano: " + textoOriginal);

            // Imprimir el texto claro en bytes[]
            byte[] textoClaro = textoOriginal.getBytes();
            System.out.println("Input en bytes[]: ");
            imprimir(textoClaro);

            // Generación de llaves simestricas
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITMO);
            generator.initialize(1024);
            KeyPair keyPair = generator.generateKeyPair();
            PublicKey llavePublica = keyPair.getPublic();
            PrivateKey llavePrivada = keyPair.getPrivate();

            // Cifrar el texto
            long tiempoInicial = System.nanoTime();
            byte[] textoCifrado = CifradoAsimetrico.cifrar(llavePublica, ALGORITMO, textoOriginal);
            long tiempoFinal = System.nanoTime();
            long tiempoTotal = tiempoFinal - tiempoInicial;
            
            System.out.println("Texto cifrado (en bytes):");
            imprimir(textoCifrado);
            System.out.println("Tiempo de cifrado: " + tiempoTotal + " ns");

            // Descifrar el texto
            long tiempoInicialDescifrado = System.nanoTime();
            byte[] textoDescifrado = CifradoAsimetrico.descifrar(llavePrivada, ALGORITMO, textoCifrado);
            long tiempoFinalDescifrado = System.nanoTime();
            long tiempoTotalDescifrado = tiempoFinalDescifrado - tiempoInicialDescifrado;
            
            System.out.println("\nTexto descifrado (reconstruido desde texto cifrado):");
            imprimir(textoDescifrado);
            // Imprimir el tiempo de descifrado
            System.out.println("Tiempo de descifrado: " + tiempoTotalDescifrado + " ns.");

            // Imprimir el texto descifrado en texto claro
            String textoDescifradoString = new String(textoDescifrado);
            System.out.println("Input descifrado convertido a texto plano: " + textoDescifradoString);

            // Tiempo total
            System.out.println("Tiempo total de cifrado y descifrado: " + (tiempoTotalDescifrado + tiempoTotal) + " ns.");
        }catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
        }
    }
}
