import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;

public class Utilidades {

    // Método para serializar (guardar) un objeto en un archivo
    public static void serializarObjeto(Object objeto, String rutaArchivo) throws Exception {
        try (FileOutputStream fileOut = new FileOutputStream(rutaArchivo);
             ObjectOutputStream objOut = new ObjectOutputStream(fileOut)) {
            objOut.writeObject(objeto);
        }
    }

    // Método para deserializar (cargar) un objeto desde un archivo (contenido en bytes)
    public static Object deserializarObjeto(byte[] contenidoArchivo) throws Exception {
        try (ObjectInputStream objIn = new ObjectInputStream(new java.io.ByteArrayInputStream(contenidoArchivo))) {
            return objIn.readObject();
        }
    }
}
