import java.math.BigInteger;

public class Hellman {

    // Parámetros constantes de Diffie-Hellman (ejemplo seguro de 2048 bits si quieres luego actualizar)
    private static final String P_HEX = 
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
        "FFFFFFFFFFFFFFFF";
    
    private static final BigInteger P = new BigInteger(P_HEX, 16);
    private static final BigInteger G = BigInteger.valueOf(2); // Generador típico

    // Métodos estáticos para obtener p y g
    public static BigInteger getP() {
        return P;
    }

    public static BigInteger getG() {
        return G;
    }
}