import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Cliente {

    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 12345;
    private static final String SERVER_PUBLIC_KEY_FILE = "public.key";
    private PublicKey serverPublicKey;

    public static void main(String[] args) {
        Cliente client = new Cliente();
        try {
            client.leerLlavePublica(); // Leer la llave pública del servidor
            client.run(); // Ejecutar el cliente
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void run() {
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.println("Seleccione el modo de operación: \n 1. Iterativo");
            int mode = scanner.nextInt();
            if (mode == 1) {
                runIterative(); // Ejecutar en modo iterativo
            }
            scanner.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void leerLlavePublica() throws Exception {
        byte[] publicKeyBytes = leerLLaveArchivo(SERVER_PUBLIC_KEY_FILE);
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        serverPublicKey = keyFactory.generatePublic(publicSpec);
    }

    private byte[] leerLLaveArchivo(String filename) throws IOException {
        File file = new File(filename);
        FileInputStream fis = new FileInputStream(file);
        byte[] keyBytes = new byte[(int) file.length()];
        fis.read(keyBytes);
        fis.close();
        return keyBytes;
    }

    private void runIterative() {
        for (int i = 0; i < 32; i++) {
            sendRequest("user" + i, "pkg" + i);
        }
    }

    public long[] sendRequest(String uid, String packageId) {
        long[] times = new long[3];
        try {
            Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
    
            // Paso 1: Enviar "SECINIT" al servidor
            out.writeUTF("HELLO");
            out.flush();
            System.out.println("MENSAJE ENVIADO");
    
            // Paso 2a: Generar desafío aleatorio (Reto)
            SecureRandom random = new SecureRandom();
            byte[] retoBytes = new byte[16]; // Desafío de 16 bytes
            random.nextBytes(retoBytes);
            String reto = Base64.getEncoder().encodeToString(retoBytes);
    
            // Cifrar Reto con la llave pública del servidor
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encryptedReto = rsaCipher.doFinal(reto.getBytes());
    
            // Paso 2b: Enviar Reto cifrado (R) al servidor
            out.writeInt(encryptedReto.length);
            out.write(encryptedReto);
            out.flush();
    
            // Paso 4: Recibir Rta del servidor
            int rtaLength = in.readInt();
            byte[] rtaBytes = new byte[rtaLength];
            in.readFully(rtaBytes);
            String rta = new String(rtaBytes);
    
            // Paso 5: Verificar que Rta == Reto
            if (!reto.equals(rta)) {
                System.out.println("Autenticación del servidor fallida.");
                out.writeUTF("ERROR");
                socket.close();
                return times;
            } else {
                out.writeUTF("OK");
                out.flush();
            }
    
            // Paso 8: Recibir G, P, G^x y firma del servidor
            int gLength = in.readInt();
            byte[] gBytes = new byte[gLength];
            in.readFully(gBytes);
            BigInteger g = new BigInteger(gBytes);
    
            int pLength = in.readInt();
            byte[] pBytes = new byte[pLength];
            in.readFully(pBytes);
            BigInteger p = new BigInteger(pBytes);
    
            int gxLength = in.readInt();
            byte[] gxBytes = new byte[gxLength];
            in.readFully(gxBytes);
            BigInteger gx = new BigInteger(gxBytes);
    
            int sigLength = in.readInt();
            byte[] sigBytes = new byte[sigLength];
            in.readFully(sigBytes);
    
            // Paso 9: Verificar firma
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(serverPublicKey);
            signature.update(gBytes);
            signature.update(pBytes);
            signature.update(gxBytes);
    
            if (!signature.verify(sigBytes)) {
                System.out.println("Firma de Diffie-Hellman no válida.");
                out.writeUTF("ERROR");
                socket.close();
                return times;
            } else {
                out.writeUTF("OK");
                out.flush();
            }
    
            // Paso 11a: Calcular G^y y derivar llaves
            SecureRandom randomY = new SecureRandom();
            BigInteger y = new BigInteger(1024, randomY);
            BigInteger gy = g.modPow(y, p);
    
            // Enviar G^y al servidor
            byte[] gyBytes = gy.toByteArray();
            out.writeInt(gyBytes.length);
            out.write(gyBytes);
            out.flush();
    
            // Calcular secreto compartido K = (G^x)^y mod p
            BigInteger sharedSecret = gx.modPow(y, p);
            byte[] sharedSecretBytes = sharedSecret.toByteArray();
    
            // Calcular digest SHA-512 de la llave maestra
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecretBytes);
    
            // Dividir digest en dos llaves de 32 bytes
            byte[] keyEncryption = Arrays.copyOfRange(digest, 0, 32); // Primeros 256 bits
            byte[] keyHMAC = Arrays.copyOfRange(digest, 32, 64); // Últimos 256 bits
    
            SecretKeySpec aesKey = new SecretKeySpec(keyEncryption, "AES");
            SecretKeySpec hmacKey = new SecretKeySpec(keyHMAC, "HmacSHA384");
    
            // Paso 12: Enviar IV al servidor
            byte[] ivBytes = new byte[16]; // IV de 16 bytes
            random.nextBytes(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    
            out.writeInt(ivBytes.length);
            out.write(ivBytes);
            out.flush();
    
            // Preparar cifrador AES
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(hmacKey);
    
            // Paso 13: Enviar uid cifrado y HMAC
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            byte[] encUid = aesCipher.doFinal(uid.getBytes());
            byte[] hmacUid = hmac.doFinal(encUid);
    
            out.writeInt(encUid.length);
            out.write(encUid);
    
            out.writeInt(hmacUid.length);
            out.write(hmacUid);
            out.flush();
    
    
            // Paso 18: Terminar
            socket.close();
    
        } catch (Exception e) {
            e.printStackTrace();
        }
        return times;
    }
}
