import java.util.Base64;

public class ServerInterceptor {

    public ServerInterceptor() {
        System.out.println("[Server] MITM mode (honest relay)");
    }

    /**
     * Relaye un message entre clients sans modification
     * @param message message Base64 envoyé par le client
     * @param fromClient client émetteur (1 ou 2)
     * @param toClient client destinataire (1 ou 2)
     * @return message Base64 à renvoyer au destinataire
     */
    public String onMessageRelay(String message, int fromClient, int toClient) {
        // Log pour MITM
        System.out.println("[MITM] Intercepted from client " + fromClient);
        // Relai honnête : ne rien toucher
        return message;
    }

    /**
     * Cette fonction effectue le handshake MITM.
     * Pour un relai honnête, on ne fait rien de spécial : juste renvoyer la clé publique du client
     */
    public String performHandshake(String clientPublicB64, int clientId) {
        // Relai honnête : on ne change pas la clé publique
        return clientPublicB64;
    }
}