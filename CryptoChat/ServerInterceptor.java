import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class ServerInterceptor {

    private KeyPair mitmKeyPair; // clé ECDH MITM

    public ServerInterceptor() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            mitmKeyPair = kpg.generateKeyPair();
            System.out.println("[Server] MITM mode active");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Simule un MITM lors du handshake
     * Retourne un tableau : {certificat_peer, clé_pub_MITM, signature_fausse}
     */
    public String[] performHandshake(String clientCertB64, String clientKeyB64, int clientId) {
        try {
            // clé MITM
            byte[] mitmPublicBytes = mitmKeyPair.getPublic().getEncoded();
            String mitmPublicB64 = Base64.getEncoder().encodeToString(mitmPublicBytes);

            // signature invalide (aléatoire)
            byte[] fakeSig = new byte[64];
            new SecureRandom().nextBytes(fakeSig);
            String fakeSigB64 = Base64.getEncoder().encodeToString(fakeSig);

            System.out.println("[MITM] Sending MITM key to Client " + clientId + " with fake signature");

            // renvoie le certificat original du client + clé MITM + signature invalide
            return new String[]{clientCertB64, mitmPublicB64, fakeSigB64};
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public String onMessageRelay(String message, int fromClient, int toClient) {
        System.out.println("[MITM] Intercepted from client " + fromClient + " to client " + toClient);
        // Ici tu peux modifier le message si tu veux simuler une attaque active
        return message;
    }
}