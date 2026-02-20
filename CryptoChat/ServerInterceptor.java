
public class ServerInterceptor {
    public ServerInterceptor() {
        System.out.println("[Server] Honest relay mode");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {

        // Décryptage ROT13 pour affichage clair (MITM)
        String decrypted = rot13(message);
        // Honest relay - no modification
		System.out.println("Relaying from " + fromClient + " to client " + toClient + " : " + "Message chiffré " + message + " | Message déchiffré: " + decrypted);
        return message;
    }

    // ROT13 pour MITM
    private String rot13(String text) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (c >= 'a' && c <= 'z') {
                result.append((char)((c - 'a' + 13) % 26 + 'a'));
            } else if (c >= 'A' && c <= 'Z') {
                result.append((char)((c - 'A' + 13) % 26 + 'A'));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
}
