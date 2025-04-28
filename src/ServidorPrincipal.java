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
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Servidor Principal para sistema de consulta de servicios de aerolínea.
 * Implementa comunicación segura con el cliente usando protocolos de cifrado.
 */
public class ServidorPrincipal {

    // Configuración del servidor
    private static final int PUERTO = 12345;
    private static final String ARCHIVO_LLAVE_PRIVADA = "private.key";
    private static final String ARCHIVO_LLAVE_PUBLICA = "public.key";
    
    // Socket del servidor
    private ServerSocket socketServidor;
    
    // Llaves RSA
    private PrivateKey llavePrivada;
    private PublicKey llavePublica;
    
    // Tabla de servicios
    private Map<String, Servicio> tablaServicios;
    
    // Contadores para estadísticas
    private AtomicInteger conexionesExitosas = new AtomicInteger(0);
    private AtomicInteger conexionesFallidas = new AtomicInteger(0);
    
    // Acumuladores de tiempos para estadísticas
    private Map<String, Long> tiemposTotales = new ConcurrentHashMap<>();

    /**
     * Constructor que inicializa el servidor
     */
    public ServidorPrincipal() {
        try {
            leerLlavesRSA();
            inicializarTablaServicios();
            
            // Inicializar contadores de tiempos
            tiemposTotales.put("firma", 0L);
            tiemposTotales.put("cifrado", 0L);
            tiemposTotales.put("verificacion", 0L);
            tiemposTotales.put("cifradoRSA", 0L);
        } catch (Exception e) {
            System.err.println("Error al inicializar el servidor: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Clase interna para representar un servicio
     */
    private class Servicio {
        private String id;
        private String nombre;
        private String ip;
        private int puerto;
        
        public Servicio(String id, String nombre, String ip, int puerto) {
            this.id = id;
            this.nombre = nombre;
            this.ip = ip;
            this.puerto = puerto;
        }
        
        @Override
        public String toString() {
            return id + "," + nombre + "," + ip + "," + puerto;
        }
        
        public String getIpPuerto() {
            return ip + ":" + puerto;
        }
    }
    
    /**
     * Inicializa la tabla de servicios disponibles
     */
    private void inicializarTablaServicios() {
        tablaServicios = new HashMap<>();
        
        // Agregar servicios predefinidos
        tablaServicios.put("1", new Servicio("1", "Estado de vuelo", "192.168.1.10", 8080));
        tablaServicios.put("2", new Servicio("2", "Disponibilidad de vuelos", "192.168.1.11", 8081));
        tablaServicios.put("3", new Servicio("3", "Costo de vuelo", "192.168.1.12", 8082));
        tablaServicios.put("4", new Servicio("4", "Reserva de vuelo", "192.168.1.13", 8083));
        tablaServicios.put("5", new Servicio("5", "Check-in online", "192.168.1.14", 8084));
    }
    
    /**
     * Convierte la tabla de servicios a formato String
     */
    private String obtenerTablaServiciosStr() {
        StringBuilder sb = new StringBuilder();
        for (Servicio servicio : tablaServicios.values()) {
            sb.append(servicio.toString()).append("\n");
        }
        return sb.toString().trim();
    }

    /**
     * Método principal que inicia la ejecución del servidor
     */
    public static void main(String[] args) {
        ServidorPrincipal servidor = new ServidorPrincipal();
        servidor.iniciarServidor();
    }

    /**
     * Menú principal para seleccionar operaciones del servidor
     */
    private void iniciarServidor() {
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("Para iniciar el programa seleccione una opción:");
            System.out.println("1. Generar llaves RSA");
            System.out.println("2. Iniciar el servidor");
            int opcion = scanner.nextInt();

            if (opcion == 1) {
                generarLlavesRSA();
            } else if (opcion == 2) {
                leerLlavesRSA();
                System.out.println("Seleccione el modo de operación:");
                System.out.println(" 1. Iterativo (atender clientes uno a uno)");
                System.out.println(" 2. Concurrente (atender múltiples clientes simultáneamente)");
                int modo = scanner.nextInt();
                
                if (modo == 1) {
                    iniciarCasoIterativo();
                } else if (modo == 2) {
                    System.out.println("Ingrese el número de delegados concurrentes (4, 16, 32 o 64):");
                    int numDelegados = scanner.nextInt();
                    iniciarCasoConcurrente(numDelegados);
                }
            }
        } catch (Exception e) {
            System.err.println("Error al iniciar el servidor: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Genera un nuevo par de llaves RSA y las guarda en archivos
     */
    private void generarLlavesRSA() throws Exception {
        KeyPairGenerator generadorLlaves = KeyPairGenerator.getInstance("RSA");
        generadorLlaves.initialize(1024);
        KeyPair parLlaves = generadorLlaves.generateKeyPair();
        llavePrivada = parLlaves.getPrivate();
        llavePublica = parLlaves.getPublic();

        guardarLlave(ARCHIVO_LLAVE_PRIVADA, llavePrivada.getEncoded());
        guardarLlave(ARCHIVO_LLAVE_PUBLICA, llavePublica.getEncoded());

        System.out.println("Llaves RSA creadas y guardadas correctamente");
    }

    /**
     * Lee las llaves RSA desde archivos
     */
    private void leerLlavesRSA() throws Exception {
        byte[] bytesLlavePrivada = leerLlaveArchivo(ARCHIVO_LLAVE_PRIVADA);
        PKCS8EncodedKeySpec especPrivada = new PKCS8EncodedKeySpec(bytesLlavePrivada);
        KeyFactory fabricaLlaves = KeyFactory.getInstance("RSA");
        llavePrivada = fabricaLlaves.generatePrivate(especPrivada);
    
        byte[] bytesLlavePublica = leerLlaveArchivo(ARCHIVO_LLAVE_PUBLICA);
        X509EncodedKeySpec especPublica = new X509EncodedKeySpec(bytesLlavePublica);
        llavePublica = fabricaLlaves.generatePublic(especPublica);
    
        System.out.println("Llaves RSA leídas desde los archivos existentes.");
    }

    /**
     * Guarda bytes en un archivo
     */
    private void guardarLlave(String archivo, byte[] bytesLlave) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(archivo)) {
            fos.write(bytesLlave);
        }
    }

    /**
     * Lee bytes desde un archivo
     */
    private byte[] leerLlaveArchivo(String archivo) throws IOException {
        File arch = new File(archivo);
        try (FileInputStream fis = new FileInputStream(arch)) {
            byte[] bytesArchivo = new byte[(int) arch.length()];
            fis.read(bytesArchivo);
            return bytesArchivo;
        }
    }

    /**
     * Inicia el servidor en modo iterativo
     */
    public void iniciarCasoIterativo() throws IOException {
        socketServidor = new ServerSocket(PUERTO);
        System.out.println("Servidor caso iterativo iniciado en el puerto " + PUERTO);
        
        // Reiniciar contadores y acumuladores
        conexionesExitosas.set(0);
        conexionesFallidas.set(0);
        for (String key : tiemposTotales.keySet()) {
            tiemposTotales.put(key, 0L);
        }
        
        int numPeticiones = 0;
        
        try {
            while (numPeticiones < 32) {
                System.out.println("Esperando conexión del cliente " + (numPeticiones + 1) + "...");
                Socket socket = socketServidor.accept();
                try {
                    procesarConexion(socket);
                    conexionesExitosas.incrementAndGet();
                    numPeticiones++;
                } catch (Exception e) {
                    System.err.println("Error al procesar la conexión: " + e.getMessage());
                    conexionesFallidas.incrementAndGet();
                }
            }
            
            // Mostrar estadísticas
            mostrarEstadisticas();
            
        } catch (Exception e) {
            System.err.println("Error en el caso iterativo: " + e.getMessage());
        } finally {
            socketServidor.close();
        }
    }
    
    /**
     * Inicia el servidor en modo concurrente con el número de delegados especificado
     */
    public void iniciarCasoConcurrente(int numDelegados) throws IOException {
        socketServidor = new ServerSocket(PUERTO);
        System.out.println("Servidor caso concurrente iniciado en el puerto " + PUERTO + " con " + numDelegados + " delegados");
        
        // Reiniciar contadores y acumuladores
        conexionesExitosas.set(0);
        conexionesFallidas.set(0);
        for (String key : tiemposTotales.keySet()) {
            tiemposTotales.put(key, 0L);
        }
        
        // Crear pool de hilos para delegados
        ExecutorService ejecutor = Executors.newFixedThreadPool(numDelegados);
        
        try {
            int clientesAtendidos = 0;
            
            while (clientesAtendidos < numDelegados) {
                System.out.println("Esperando conexión del cliente " + (clientesAtendidos + 1) + " de " + numDelegados + "...");
                Socket socketCliente = socketServidor.accept();
                
                // Crear un delegado para atender al cliente
                ejecutor.submit(() -> {
                    try {
                        procesarConexion(socketCliente);
                        conexionesExitosas.incrementAndGet();
                    } catch (Exception e) {
                        System.err.println("Error en delegado: " + e.getMessage());
                        conexionesFallidas.incrementAndGet();
                    }
                });
                
                clientesAtendidos++;
            }
            
            // Esperar a que terminen todos los delegados
            ejecutor.shutdown();
            while (!ejecutor.isTerminated()) {
                Thread.sleep(100);
            }
            
            // Mostrar estadísticas
            mostrarEstadisticas();
            
        } catch (Exception e) {
            System.err.println("Error en el caso concurrente: " + e.getMessage());
        } finally {
            socketServidor.close();
            System.out.println("Servidor cerrado.");
        }
    }
    
    /**
     * Procesa una conexión con un cliente siguiendo el protocolo de comunicación
     */
    private void procesarConexion(Socket socket) throws Exception {
        DataInputStream entrada = new DataInputStream(socket.getInputStream());
        DataOutputStream salida = new DataOutputStream(socket.getOutputStream());
        
        try {
            // Paso 1: Recibir HELLO del cliente
            String mensaje = entrada.readUTF();
            if (!"HELLO".equals(mensaje)) {
                throw new Exception("Protocolo incorrecto: Se esperaba HELLO");
            }
            
            // Paso 2: Recibir Reto cifrado
            int longitudReto = entrada.readInt();
            byte[] retoCifrado = new byte[longitudReto];
            entrada.readFully(retoCifrado);
            
            // Paso 3: Descifrar el Reto con la llave privada del servidor
            Cipher descifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            descifrador.init(Cipher.DECRYPT_MODE, llavePrivada);
            byte[] retoBytes = descifrador.doFinal(retoCifrado);
            String reto = new String(retoBytes);
            
            // Paso 4: Enviar Rta (el reto descifrado) al cliente
            salida.writeInt(reto.getBytes().length);
            salida.write(reto.getBytes());
            salida.flush();
            
            // Paso 5: Recibir OK del cliente
            String confirmacion = entrada.readUTF();
            if (!"OK".equals(confirmacion)) {
                throw new Exception("Error en la autenticación");
            }
            
            // Paso 6-7: Generar parámetros Diffie-Hellman
            SecureRandom random = new SecureRandom();
            // Generar primo p de 1024 bits
            BigInteger p = BigInteger.probablePrime(1024, random);
            // Generar raíz primitiva g
            BigInteger g = BigInteger.valueOf(2); // Usamos 2 como generador común
            
            // Generar exponente privado x
            BigInteger x = new BigInteger(1024, random);
            // Calcular G^x mod p
            BigInteger gx = g.modPow(x, p);
            
            // Paso 8: Firmar y enviar parámetros
            long tiempoInicioFirma = System.nanoTime();
            Signature firmador = Signature.getInstance("SHA256withRSA");
            firmador.initSign(llavePrivada);
            firmador.update(g.toByteArray());
            firmador.update(p.toByteArray());
            firmador.update(gx.toByteArray());
            byte[] firma = firmador.sign();
            
            long tiempoFirma = System.nanoTime() - tiempoInicioFirma;
            synchronized (tiemposTotales) {
                tiemposTotales.put("firma", tiemposTotales.get("firma") + tiempoFirma);
            }
            
            // Enviar G
            byte[] bytesG = g.toByteArray();
            salida.writeInt(bytesG.length);
            salida.write(bytesG);
            
            // Enviar P
            byte[] bytesP = p.toByteArray();
            salida.writeInt(bytesP.length);
            salida.write(bytesP);
            
            // Enviar G^x
            byte[] bytesGx = gx.toByteArray();
            salida.writeInt(bytesGx.length);
            salida.write(bytesGx);
            
            // Enviar Firma
            salida.writeInt(firma.length);
            salida.write(firma);
            salida.flush();
            
            // Paso 9-10: Recibir confirmación del cliente
            String confirmacionFirma = entrada.readUTF();
            if (!"OK".equals(confirmacionFirma)) {
                throw new Exception("Error en la verificación de la firma");
            }
            
            // Paso 11: Recibir G^y del cliente
            int longitudGy = entrada.readInt();
            byte[] bytesGy = new byte[longitudGy];
            entrada.readFully(bytesGy);
            BigInteger gy = new BigInteger(bytesGy);
            
            // Calcular secreto compartido K = (G^y)^x mod p
            BigInteger secretoCompartido = gy.modPow(x, p);
            byte[] bytesSecreto = secretoCompartido.toByteArray();
            
            // Calcular digest SHA-512 del secreto compartido
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(bytesSecreto);
            
            // Dividir digest en dos llaves de 32 bytes
            byte[] llaveCifrado = Arrays.copyOfRange(digest, 0, 32); // Primeros 256 bits
            byte[] llaveHMAC = Arrays.copyOfRange(digest, 32, 64); // Últimos 256 bits
            
            SecretKeySpec llaveAES = new SecretKeySpec(llaveCifrado, "AES");
            SecretKeySpec llaveHmac = new SecretKeySpec(llaveHMAC, "HmacSHA384");
            
            // Paso 12: Recibir IV del cliente
            int longitudIV = entrada.readInt();
            byte[] bytesIV = new byte[longitudIV];
            entrada.readFully(bytesIV);
            IvParameterSpec ivSpec = new IvParameterSpec(bytesIV);
            
            Cipher cifradorAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(llaveHmac);
            
            // Paso 13-14: Recibir uid cifrado y HMAC
            int longitudUidCifrado = entrada.readInt();
            byte[] uidCifrado = new byte[longitudUidCifrado];
            entrada.readFully(uidCifrado);
            
            int longitudHmacUid = entrada.readInt();
            byte[] hmacUid = new byte[longitudHmacUid];
            entrada.readFully(hmacUid);
            
            // Verificar HMAC del uid
            long tiempoInicioVerificacion = System.nanoTime();
            byte[] hmacUidCalculado = hmac.doFinal(uidCifrado);
            if (!Arrays.equals(hmacUid, hmacUidCalculado)) {
                throw new Exception("Error en la verificación: HMAC de uid inválido");
            }
            long tiempoVerificacion = System.nanoTime() - tiempoInicioVerificacion;
            synchronized (tiemposTotales) {
                tiemposTotales.put("verificacion", tiemposTotales.get("verificacion") + tiempoVerificacion);
            }
            
            // Descifrar uid
            cifradorAES.init(Cipher.DECRYPT_MODE, llaveAES, ivSpec);
            byte[] bytesUid = cifradorAES.doFinal(uidCifrado);
            String uid = new String(bytesUid);
            
            // Paso 15: Cifrar y enviar tabla de servicios con HMAC
            String tablaServiciosStr = obtenerTablaServiciosStr();
            
            // Cifrar tabla
            long tiempoInicioCifrado = System.nanoTime();
            cifradorAES.init(Cipher.ENCRYPT_MODE, llaveAES, ivSpec);
            byte[] tablaCifrada = cifradorAES.doFinal(tablaServiciosStr.getBytes());
            long tiempoCifrado = System.nanoTime() - tiempoInicioCifrado;
            synchronized (tiemposTotales) {
                tiemposTotales.put("cifrado", tiemposTotales.get("cifrado") + tiempoCifrado);
            }
            
            // También medir tiempo de cifrado con RSA para comparación
            long tiempoInicioCifradoRSA = System.nanoTime();
            Cipher cifradorRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cifradorRSA.init(Cipher.ENCRYPT_MODE, llavePublica);
            // RSA solo puede cifrar bloques pequeños, así que cifraremos solo una parte para comparar
            byte[] fragmentoTabla = Arrays.copyOf(tablaServiciosStr.getBytes(), 100); // Solo los primeros 100 bytes
            cifradorRSA.doFinal(fragmentoTabla);
            long tiempoCifradoRSA = System.nanoTime() - tiempoInicioCifradoRSA;
            synchronized (tiemposTotales) {
                tiemposTotales.put("cifradoRSA", tiemposTotales.get("cifradoRSA") + tiempoCifradoRSA);
            }
            
            // Generar HMAC de la tabla cifrada
            byte[] hmacTabla = hmac.doFinal(tablaCifrada);
            
            // Enviar tabla cifrada y su HMAC
            salida.writeInt(tablaCifrada.length);
            salida.write(tablaCifrada);
            
            salida.writeInt(hmacTabla.length);
            salida.write(hmacTabla);
            salida.flush();
            
            // Paso 16: Recibir consulta del cliente (id servicio cifrado y HMAC)
            int longitudIdServicioCifrado = entrada.readInt();
            byte[] idServicioCifrado = new byte[longitudIdServicioCifrado];
            entrada.readFully(idServicioCifrado);
            
            int longitudHmacIdServicio = entrada.readInt();
            byte[] hmacIdServicio = new byte[longitudHmacIdServicio];
            entrada.readFully(hmacIdServicio);
            
            // Verificar HMAC del id servicio
            byte[] hmacIdServicioCalculado = hmac.doFinal(idServicioCifrado);
            if (!Arrays.equals(hmacIdServicio, hmacIdServicioCalculado)) {
                throw new Exception("Error en la verificación: HMAC de id servicio inválido");
            }
            
            // Descifrar id servicio
            cifradorAES.init(Cipher.DECRYPT_MODE, llaveAES, ivSpec);
            byte[] bytesIdServicio = cifradorAES.doFinal(idServicioCifrado);
            String idServicio = new String(bytesIdServicio);
            
            // Paso 17: Buscar servicio y enviar respuesta
            String respuesta;
            if (tablaServicios.containsKey(idServicio)) {
                Servicio servicio = tablaServicios.get(idServicio);
                respuesta = servicio.getIpPuerto();
            } else {
                respuesta = "-1,-1";
            }
            
            // Cifrar respuesta
            cifradorAES.init(Cipher.ENCRYPT_MODE, llaveAES, ivSpec);
            byte[] respuestaCifrada = cifradorAES.doFinal(respuesta.getBytes());
            
            // Generar HMAC de la respuesta cifrada
            byte[] hmacRespuesta = hmac.doFinal(respuestaCifrada);
            
            // Enviar respuesta cifrada y su HMAC
            salida.writeInt(respuestaCifrada.length);
            salida.write(respuestaCifrada);
            
            salida.writeInt(hmacRespuesta.length);
            salida.write(hmacRespuesta);
            salida.flush();
            
            // Devolver también el tiempo de firma para que el cliente lo reporte
            salida.writeLong(tiempoFirma);
            salida.flush();
            
            System.out.println("Conexión procesada exitosamente para cliente con UID: " + uid);
            
        } catch (Exception e) {
            System.err.println("Error en procesarConexion: " + e.getMessage());
            throw e;
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                System.err.println("Error al cerrar el socket: " + e.getMessage());
            }
        }
    }
    
    /**
     * Muestra las estadísticas de tiempos y conexiones
     */
    private void mostrarEstadisticas() {
        System.out.println("\n==== Estadísticas del Servidor ====");
        System.out.println("Conexiones exitosas: " + conexionesExitosas.get());
        System.out.println("Conexiones fallidas: " + conexionesFallidas.get());
        
        if (conexionesExitosas.get() > 0) {
            long promedioFirma = tiemposTotales.get("firma") / conexionesExitosas.get();
            long promedioCifrado = tiemposTotales.get("cifrado") / conexionesExitosas.get();
            long promedioVerificacion = tiemposTotales.get("verificacion") / conexionesExitosas.get();
            long promedioCifradoRSA = tiemposTotales.get("cifradoRSA") / conexionesExitosas.get();
            
            System.out.println("Tiempo promedio de firma: " + promedioFirma + " ns");
            System.out.println("Tiempo promedio de cifrado simétrico: " + promedioCifrado + " ns");
            System.out.println("Tiempo promedio de verificación: " + promedioVerificacion + " ns");
            System.out.println("Tiempo promedio de cifrado asimétrico (RSA): " + promedioCifradoRSA + " ns");
            System.out.println("Relación cifrado RSA/AES: " + (double)promedioCifradoRSA / promedioCifrado);
        }
        
        System.out.println("=================================");
    }
}