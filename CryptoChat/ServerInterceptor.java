import java.util.Base64;

public class ServerInterceptor {
    public ServerInterceptor() {
        System.out.println("[Server] Honest relay mode");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {

        byte[] data = Base64.getDecoder().decode(message);
        data[16] ^= 1; // flip un bit du ciphertext
        return Base64.getEncoder().encodeToString(data);

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
