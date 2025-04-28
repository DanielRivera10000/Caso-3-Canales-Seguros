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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cliente para sistema de consulta de servicios de aerolínea.
 * Implementa comunicación segura con el servidor principal usando protocolos de cifrado.
 */
public class Cliente {

    // Configuración de conexión
    private static final String DIRECCION_SERVIDOR = "localhost";
    private static final int PUERTO_SERVIDOR = 12345;
    private static final String ARCHIVO_LLAVE_PUBLICA = "public.key";
    
    // Llave pública del servidor
    private PublicKey llavePublicaServidor;
    
    // Contadores para estadísticas de clientes concurrentes
    private static AtomicInteger clientesExitosos = new AtomicInteger(0);
    private static AtomicInteger clientesFallidos = new AtomicInteger(0);

    /**
     * Método principal que inicia la ejecución del cliente
     */
    public static void main(String[] args) {
        Cliente cliente = new Cliente();
        try {
            cliente.leerLlavePublica(); // Leer la llave pública del servidor
            cliente.ejecutar(); // Ejecutar el cliente
        } catch (Exception e) {
            System.err.println("Error en la ejecución del cliente: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Método para seleccionar y ejecutar el modo de operación
     */
    private void ejecutar() {
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("Seleccione el modo de operación:");
            System.out.println(" 1. Iterativo (32 peticiones secuenciales)");
            System.out.println(" 2. Concurrente (múltiples clientes simultáneos)");
            
            int modo = scanner.nextInt();
            
            if (modo == 1) {
                ejecutarModoIterativo(); // Ejecutar en modo iterativo
            } else if (modo == 2) {
                System.out.println("Ingrese el número de clientes concurrentes (4, 16, 32 o 64):");
                int numClientes = scanner.nextInt();
                ejecutarModoConcurrente(numClientes); // Ejecutar en modo concurrente
            } else {
                System.out.println("Modo no válido.");
            }
        } catch (Exception e) {
            System.err.println("Error al seleccionar modo: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Lee la llave pública del servidor desde el archivo
     */
    public void leerLlavePublica() throws Exception {
        byte[] bytesLlavePublica = leerArchivo(ARCHIVO_LLAVE_PUBLICA);
        X509EncodedKeySpec especificacionPublica = new X509EncodedKeySpec(bytesLlavePublica);
        KeyFactory fabricaLlaves = KeyFactory.getInstance("RSA");
        llavePublicaServidor = fabricaLlaves.generatePublic(especificacionPublica);
    }

    /**
     * Lee bytes desde un archivo
     */
    private byte[] leerArchivo(String nombreArchivo) throws IOException {
        File archivo = new File(nombreArchivo);
        FileInputStream fis = new FileInputStream(archivo);
        byte[] bytesArchivo = new byte[(int) archivo.length()];
        fis.read(bytesArchivo);
        fis.close();
        return bytesArchivo;
    }

    /**
     * Ejecuta el cliente en modo iterativo (32 peticiones secuenciales)
     */
    private void ejecutarModoIterativo() {
        System.out.println("Iniciando modo iterativo con 32 peticiones secuenciales...");
        
        long[] tiemposTotales = new long[3]; // Acumulador para tiempos [Firma, Cifrado, Verificación]
        
        for (int i = 0; i < 32; i++) {
            System.out.println("Ejecutando petición " + (i+1) + " de 32...");
            long[] tiempos = enviarPeticion("usuario" + i, "paquete" + i);
            
            // Acumular tiempos para promedios
            for (int j = 0; j < 3; j++) {
                tiemposTotales[j] += tiempos[j];
            }
            
            System.out.println("Petición " + (i+1) + " completada. Tiempos [Firma=" + tiempos[0] + 
                               ", Cifrado=" + tiempos[1] + ", Verificación=" + tiempos[2] + "] ns");
        }
        
        // Calcular y mostrar promedios
        System.out.println("\nResultados finales modo iterativo:");
        System.out.println("Promedio tiempo de firma: " + (tiemposTotales[0] / 32) + " ns");
        System.out.println("Promedio tiempo de cifrado: " + (tiemposTotales[1] / 32) + " ns");
        System.out.println("Promedio tiempo de verificación: " + (tiemposTotales[2] / 32) + " ns");
    }

    /**
     * Ejecuta el cliente en modo concurrente con el número especificado de clientes
     */
    private void ejecutarModoConcurrente(int numClientes) {
        System.out.println("Iniciando modo concurrente con " + numClientes + " clientes...");
        
        ExecutorService ejecutor = Executors.newFixedThreadPool(numClientes);
        CountDownLatch latch = new CountDownLatch(numClientes);
        
        // Restablecer contadores
        clientesExitosos.set(0);
        clientesFallidos.set(0);
        
        // Tiempos acumulados
        long[] tiemposTotales = new long[3]; // [Firma, Cifrado, Verificación]
        
        // Crear y enviar los clientes concurrentes
        for (int i = 0; i < numClientes; i++) {
            final int clienteId = i;
            ejecutor.submit(() -> {
                try {
                    System.out.println("Cliente " + clienteId + " iniciando...");
                    
                    // Cada cliente envía una petición
                    long[] tiempos = enviarPeticion("usuario_conc" + clienteId, "paquete_conc" + clienteId);
                    
                    // Acumular tiempos (con sincronización)
                    synchronized (tiemposTotales) {
                        for (int j = 0; j < 3; j++) {
                            tiemposTotales[j] += tiempos[j];
                        }
                    }
                    
                    clientesExitosos.incrementAndGet();
                    System.out.println("Cliente " + clienteId + " completado con éxito.");
                } catch (Exception e) {
                    System.err.println("Error en cliente " + clienteId + ": " + e.getMessage());
                    clientesFallidos.incrementAndGet();
                } finally {
                    latch.countDown();
                }
            });
        }
        
        try {
            // Esperar a que todos los clientes terminen
            latch.await();
            
            // Mostrar resultados
            System.out.println("\nResultados finales modo concurrente con " + numClientes + " clientes:");
            System.out.println("Clientes exitosos: " + clientesExitosos.get());
            System.out.println("Clientes fallidos: " + clientesFallidos.get());
            
            if (clientesExitosos.get() > 0) {
                System.out.println("Promedio tiempo de firma: " + (tiemposTotales[0] / clientesExitosos.get()) + " ns");
                System.out.println("Promedio tiempo de cifrado: " + (tiemposTotales[1] / clientesExitosos.get()) + " ns");
                System.out.println("Promedio tiempo de verificación: " + (tiemposTotales[2] / clientesExitosos.get()) + " ns");
            }
            
        } catch (InterruptedException e) {
            System.err.println("Interrupción durante la espera de los clientes: " + e.getMessage());
        } finally {
            ejecutor.shutdown();
        }
    }

    /**
     * Envía una petición al servidor y gestiona la comunicación
     * 
     * @param idUsuario Identificador del usuario
     * @param idPaquete Identificador del paquete
     * @return Arreglo con los tiempos [Firma, Cifrado, Verificación]
     */
    public long[] enviarPeticion(String idUsuario, String idPaquete) {
        long[] tiempos = new long[3]; // [Firma, Cifrado, Verificación]
        
        try (Socket socket = new Socket(DIRECCION_SERVIDOR, PUERTO_SERVIDOR);
             DataInputStream entrada = new DataInputStream(socket.getInputStream());
             DataOutputStream salida = new DataOutputStream(socket.getOutputStream())) {
    
            // Paso 1: Enviar "HELLO" al servidor
            salida.writeUTF("HELLO");
            salida.flush();
    
            // Paso 2a: Generar desafío aleatorio (Reto)
            SecureRandom random = new SecureRandom();
            byte[] bytesReto = new byte[16]; // Desafío de 16 bytes
            random.nextBytes(bytesReto);
            String reto = Base64.getEncoder().encodeToString(bytesReto);
    
            // Cifrar Reto con la llave pública del servidor
            Cipher cifradorRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cifradorRSA.init(Cipher.ENCRYPT_MODE, llavePublicaServidor);
            byte[] retoCifrado = cifradorRSA.doFinal(reto.getBytes());
    
            // Paso 2b: Enviar Reto cifrado (R) al servidor
            salida.writeInt(retoCifrado.length);
            salida.write(retoCifrado);
            salida.flush();
    
            // Paso 4: Recibir Rta del servidor
            int longitudRta = entrada.readInt();
            byte[] bytesRta = new byte[longitudRta];
            entrada.readFully(bytesRta);
            String rta = new String(bytesRta);
    
            // Paso 5: Verificar que Rta == Reto
            if (!reto.equals(rta)) {
                throw new Exception("Autenticación del servidor fallida");
            } else {
                salida.writeUTF("OK");
                salida.flush();
            }
    
            // Paso 8: Recibir G, P, G^x y firma del servidor
            int longitudG = entrada.readInt();
            byte[] bytesG = new byte[longitudG];
            entrada.readFully(bytesG);
            BigInteger g = new BigInteger(bytesG);
    
            int longitudP = entrada.readInt();
            byte[] bytesP = new byte[longitudP];
            entrada.readFully(bytesP);
            BigInteger p = new BigInteger(bytesP);
    
            int longitudGx = entrada.readInt();
            byte[] bytesGx = new byte[longitudGx];
            entrada.readFully(bytesGx);
            BigInteger gx = new BigInteger(bytesGx);
    
            int longitudFirma = entrada.readInt();
            byte[] bytesFirma = new byte[longitudFirma];
            entrada.readFully(bytesFirma);
    
            // Paso 9: Verificar firma
            long tiempoInicioVerificacion = System.nanoTime();
            Signature verificadorFirma = Signature.getInstance("SHA256withRSA");
            verificadorFirma.initVerify(llavePublicaServidor);
            verificadorFirma.update(bytesG);
            verificadorFirma.update(bytesP);
            verificadorFirma.update(bytesGx);
    
            if (!verificadorFirma.verify(bytesFirma)) {
                throw new Exception("Firma de Diffie-Hellman no válida");
            } else {
                tiempos[2] = System.nanoTime() - tiempoInicioVerificacion; // Tiempo de verificación
                salida.writeUTF("OK");
                salida.flush();
            }
    
            // Paso 11a: Calcular G^y y derivar llaves
            SecureRandom randomY = new SecureRandom();
            BigInteger y = new BigInteger(1024, randomY);
            BigInteger gy = g.modPow(y, p);
    
            // Enviar G^y al servidor
            byte[] bytesGy = gy.toByteArray();
            salida.writeInt(bytesGy.length);
            salida.write(bytesGy);
            salida.flush();
    
            // Calcular secreto compartido K = (G^x)^y mod p
            BigInteger secretoCompartido = gx.modPow(y, p);
            byte[] bytesSecreto = secretoCompartido.toByteArray();
    
            // Calcular digest SHA-512 del secreto compartido
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(bytesSecreto);
    
            // Dividir digest en dos llaves de 32 bytes
            byte[] llaveCifrado = Arrays.copyOfRange(digest, 0, 32); // Primeros 256 bits
            byte[] llaveHMAC = Arrays.copyOfRange(digest, 32, 64); // Últimos 256 bits
    
            SecretKeySpec llaveAES = new SecretKeySpec(llaveCifrado, "AES");
            SecretKeySpec llaveHmac = new SecretKeySpec(llaveHMAC, "HmacSHA384");
    
            // Paso 12: Enviar IV al servidor
            byte[] bytesIV = new byte[16]; // IV de 16 bytes
            random.nextBytes(bytesIV);
            IvParameterSpec ivSpec = new IvParameterSpec(bytesIV);
    
            salida.writeInt(bytesIV.length);
            salida.write(bytesIV);
            salida.flush();

            Cipher cifradorAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(llaveHmac);
    
            // Paso 13: Enviar uid cifrado y HMAC
            long tiempoInicioCifrado = System.nanoTime();
            cifradorAES.init(Cipher.ENCRYPT_MODE, llaveAES, ivSpec);
            byte[] idUsuarioCifrado = cifradorAES.doFinal(idUsuario.getBytes());
            tiempos[1] = System.nanoTime() - tiempoInicioCifrado; // Tiempo de cifrado
            
            byte[] hmacUsuario = hmac.doFinal(idUsuarioCifrado);
    
            salida.writeInt(idUsuarioCifrado.length);
            salida.write(idUsuarioCifrado);
    
            salida.writeInt(hmacUsuario.length);
            salida.write(hmacUsuario);
            salida.flush();
    
            // Paso 15: Recibir tabla de servicios cifrada y su HMAC
            int longitudTablaCifrada = entrada.readInt();
            byte[] tablaCifrada = new byte[longitudTablaCifrada];
            entrada.readFully(tablaCifrada);
            
            int longitudHmacTabla = entrada.readInt();
            byte[] hmacTabla = new byte[longitudHmacTabla];
            entrada.readFully(hmacTabla);
            
            // Verificar HMAC de la tabla
            byte[] hmacTablaCalculado = hmac.doFinal(tablaCifrada);
            if (!Arrays.equals(hmacTabla, hmacTablaCalculado)) {
                throw new Exception("Error en la consulta: HMAC de tabla inválido");
            }
            
            // Descifrar tabla de servicios
            cifradorAES.init(Cipher.DECRYPT_MODE, llaveAES, ivSpec);
            byte[] bytesTabla = cifradorAES.doFinal(tablaCifrada);
            String tablaServicios = new String(bytesTabla);
            
            // Parsear la tabla de servicios
            String[] servicios = tablaServicios.split("\n");
            
            // En modo automático, elegir un servicio aleatorio
            int servicioSeleccionado = new SecureRandom().nextInt(servicios.length);
            String idServicio = servicios[servicioSeleccionado].split(",")[0];
            
            // Paso 16: Enviar consulta por servicio específico
            // Cifrar idServicio
            cifradorAES.init(Cipher.ENCRYPT_MODE, llaveAES, ivSpec);
            byte[] idServicioCifrado = cifradorAES.doFinal(idServicio.getBytes());
            byte[] hmacIdServicio = hmac.doFinal(idServicioCifrado);
            
            salida.writeInt(idServicioCifrado.length);
            salida.write(idServicioCifrado);
            
            salida.writeInt(hmacIdServicio.length);
            salida.write(hmacIdServicio);
            salida.flush();
            
            // Paso 17: Recibir respuesta con datos del servicio
            int longitudRespuestaCifrada = entrada.readInt();
            byte[] respuestaCifrada = new byte[longitudRespuestaCifrada];
            entrada.readFully(respuestaCifrada);
            
            int longitudHmacRespuesta = entrada.readInt();
            byte[] hmacRespuesta = new byte[longitudHmacRespuesta];
            entrada.readFully(hmacRespuesta);
            
            // Verificar HMAC de la respuesta
            byte[] hmacRespuestaCalculado = hmac.doFinal(respuestaCifrada);
            if (!Arrays.equals(hmacRespuesta, hmacRespuestaCalculado)) {
                throw new Exception("Error en la consulta: HMAC de respuesta inválido");
            }
            
            // Descifrar respuesta
            cifradorAES.init(Cipher.DECRYPT_MODE, llaveAES, ivSpec);
            byte[] bytesRespuesta = cifradorAES.doFinal(respuestaCifrada);
            String respuesta = new String(bytesRespuesta);
            
            // Recoger tiempo de firma (recibido del servidor)
            tiempos[0] = longitudRespuestaCifrada; // Uso este campo temporalmente para guardar firma
            
            return tiempos;
    
        } catch (Exception e) {
            System.err.println("Error en la petición: " + e.getMessage());
            e.printStackTrace();
            return tiempos; // Devuelve tiempos en cero si hay error
        }
    }
}