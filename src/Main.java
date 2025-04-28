public class Main {






    public static void main(String[] args) {
        try {
            ServidorPrincipal servidor = new ServidorPrincipal();
            servidor.iniciarServidor();
        } catch (Exception e) {
            System.out.println("Error iniciando el servidor: " + e.getMessage());
        }
    }

}
