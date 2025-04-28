import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ServidorPrincipal {


    private static final int PORT = 12345; // Puerto del servidor
    private static final String LLAVE_PRIVADA_ARCHIVO = "private.key";
    private static final String LLAVE_PUBLICA_ARCHIVO = "public.key";
    private ServerSocket serverSocket;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ServidorPrincipal() {
        try {
            leerLlavesRSA();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        ServidorPrincipal servidor = new ServidorPrincipal();
        servidor.iniciarServidor();
    }

    private void iniciarServidor() {
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.println("Para iniciar el programa seleccione una opción:");
            System.out.println("1. Generar llaves RSA");
            System.out.println("2. Iniciar el servidor");
            int opcion = scanner.nextInt();

            if (opcion == 1) {
                generarLlavesRSA();
            } else if (opcion == 2) {
                leerLlavesRSA();
                System.out.println("Seleccione el modo de operación: \n 1. Iterativo \n 2. Concurrente");
                int modo = scanner.nextInt();
                if (modo == 1) {
                    iniciarCasoIterativo();
                }
            }
            scanner.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void generarLlavesRSA() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();

        guardarLlave(LLAVE_PRIVADA_ARCHIVO, privateKey.getEncoded());
        guardarLlave(LLAVE_PUBLICA_ARCHIVO, publicKey.getEncoded());

        System.out.println("Llaves RSA creadas y guardadas correctamente");
    }

    private void leerLlavesRSA() throws Exception {
        byte[] bytesLlavePrivada = leerLlaveArchivo(LLAVE_PRIVADA_ARCHIVO);
        PKCS8EncodedKeySpec specPrivada = new PKCS8EncodedKeySpec(bytesLlavePrivada);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(specPrivada);
    
        byte[] bytesLlavePublica = leerLlaveArchivo(LLAVE_PUBLICA_ARCHIVO);
        X509EncodedKeySpec specPublica = new X509EncodedKeySpec(bytesLlavePublica);
        publicKey = keyFactory.generatePublic(specPublica);
    
        System.out.println("Llaves RSA leídas desde los archivos que se crearon.");
    }

    private void guardarLlave(String archivo, byte[] bytesLLave) throws IOException {
        FileOutputStream fos = new FileOutputStream(archivo);
        fos.write(bytesLLave);
        fos.close();
    }

    private byte[] leerLlaveArchivo(String archivo) throws IOException {
        File arch = new File(archivo);
        FileInputStream fis = new FileInputStream(arch);
        byte[] keyBytes = new byte[(int) arch.length()];
        fis.read(keyBytes);
        fis.close();
        return keyBytes;
    }

    public void iniciarCasoIterativo() throws IOException {
        serverSocket = new ServerSocket(PORT);
        System.out.println("Servidor caso iterativo iniciado en el puerto " + PORT);
        try {
            while (!Thread.currentThread().isInterrupted()) {
                Socket socketCliente = serverSocket.accept();
                conectarConCliente(socketCliente);
            }
        } catch (IOException e) {
            e.getMessage();
        } finally {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        }
    }

    private void conectarConCliente(Socket socketCliente) {
        try (DataInputStream in = new DataInputStream(socketCliente.getInputStream());
             DataOutputStream out = new DataOutputStream(socketCliente.getOutputStream())) {
    
            // Paso 1: Recibir "HELLO" del cliente
            String hello = in.readUTF();
            if (!"HELLO".equals(hello)) {
                System.out.println("HELLO no recibido. Cerrando conexión.");
                socketCliente.close();
                return;
            }
            System.out.println("MENSAJE RECIBIDO: " + hello);
    
            // Paso 2b: Recibir desafío cifrado R del cliente
            int encryptedChallengeLength = in.readInt();
            byte[] encryptedChallenge = new byte[encryptedChallengeLength];
            in.readFully(encryptedChallenge);
    
            // Paso 3: Descifrar R para obtener el Reto
    
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] retoBytes = rsaCipher.doFinal(encryptedChallenge);
            String reto = new String(retoBytes);
    
    
            // Paso 4: Enviar Rta (Reto) de vuelta al cliente
            out.writeInt(retoBytes.length);
            out.write(retoBytes);
            out.flush();
    
            // Paso 5: Recibir "OK" o "ERROR" del cliente
            String authStatus = in.readUTF();
            if (!"OK".equals(authStatus)) {
                System.out.println("Autenticación fallida. Cerrando conexión.");
                socketCliente.close();
                return;
            }
    
            // Paso 7: Generar parámetros Diffie-Hellman G, P, G^x
    
            BigInteger p, g;
                // Usar parámetros constantes para el servidor iterativo
            p = Hellman.getP();
            g = Hellman.getG();
    
            // Generar exponente privado x y calcular G^x mod p
            SecureRandom random = new SecureRandom();
            BigInteger x = new BigInteger(1024, random);
            BigInteger gx = g.modPow(x, p);
    
    
            // Paso 8: Enviar G, P, G^x y firma al cliente
            // Serializar parámetros
            byte[] gBytes = g.toByteArray();
            byte[] pBytes = p.toByteArray();
            byte[] gxBytes = gx.toByteArray();
    
            // Firmar los parámetros
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey);
            signature.update(gBytes);
            signature.update(pBytes);
            signature.update(gxBytes);
            byte[] sigBytes = signature.sign();
    
            // Enviar longitudes y datos
            out.writeInt(gBytes.length);
            out.write(gBytes);
    
            out.writeInt(pBytes.length);
            out.write(pBytes);
    
            out.writeInt(gxBytes.length);
            out.write(gxBytes);
    
            out.writeInt(sigBytes.length);
            out.write(sigBytes);
            out.flush();
    
            // Paso 10: Recibir "OK" o "ERROR" del cliente
            String dhStatus = in.readUTF();
            if (!"OK".equals(dhStatus)) {
                System.out.println("Error en Diffie-Hellman. Cerrando conexión.");
                socketCliente.close();
                return;
            }
    
            // Paso 11b: Calcular secreto compartido y derivar llaves
            // Recibir G^y del cliente
            int gyLength = in.readInt();
            byte[] gyBytes = new byte[gyLength];
            in.readFully(gyBytes);
            BigInteger gy = new BigInteger(gyBytes);
    
            // Calcular secreto compartido K = (G^y)^x mod p
            BigInteger sharedSecret = gy.modPow(x, p);
            byte[] sharedSecretBytes = sharedSecret.toByteArray();
    
            // Calcular digest SHA-512 de la llave maestra
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecretBytes);
    
            // Dividir digest en dos llaves de 32 bytes
            byte[] keyEncryption = Arrays.copyOfRange(digest, 0, 32); // Primeros 256 bits
            byte[] keyHMAC = Arrays.copyOfRange(digest, 32, 64); // Últimos 256 bits
    
            SecretKeySpec aesKey = new SecretKeySpec(keyEncryption, "AES");
            SecretKeySpec hmacKey = new SecretKeySpec(keyHMAC, "HmacSHA384");
    
            // Paso 12: Recibir IV del cliente
            int ivLength = in.readInt();
            byte[] ivBytes = new byte[ivLength];
            in.readFully(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    
            // Preparar cifrador AES
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(hmacKey);
    
            // Paso 13: Recibir uid cifrado y HMAC
            int encUidLength = in.readInt();
            byte[] encUid = new byte[encUidLength];
            in.readFully(encUid);
    
            int hmacUidLength = in.readInt();
            byte[] hmacUid = new byte[hmacUidLength];
            in.readFully(hmacUid);
    
            // Verificar HMAC
            byte[] computedHmacUid = hmac.doFinal(encUid);
            if (!Arrays.equals(hmacUid, computedHmacUid)) {
                System.out.println("HMAC de uid no válido. Cerrando conexión.");
                socketCliente.close();
                return;
            }
            System.out.println(computedHmacUid.toString());

            socketCliente.close();
    
    
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void pararServidor() {
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
                System.out.println("Socket del servidor cerrado.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
}
