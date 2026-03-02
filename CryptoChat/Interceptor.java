import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Arrays;



// Interceptor class is responsible for handling the handshake, encrypting messages before sending, and decrypting messages after receiving.
// Client-Side Protection 
public class Interceptor {
    
    private SecretKey aesKey;

    private PrivateKey longTermPrivateKey;
    private PublicKey longTermPublicKey;

    public Interceptor(String privateKeyPath, String publicKeyPath) {
        try {
            loadLongTermKeys(privateKeyPath, publicKeyPath);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load ECDSA keys", e);
        }
    }

    private void loadLongTermKeys(String privatePath, String publicPath) throws Exception {

        KeyFactory kf = KeyFactory.getInstance("EC");

        // ----- Charger clé privée -----
        String privatePem = new String(java.nio.file.Files.readAllBytes(
                java.nio.file.Paths.get(privatePath)));

        privatePem = privatePem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] privateBytes = Base64.getDecoder().decode(privatePem);

        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privateBytes);
        longTermPrivateKey = kf.generatePrivate(privSpec);


        // ----- Charger clé publique -----
        String publicPem = new String(java.nio.file.Files.readAllBytes(
                java.nio.file.Paths.get(publicPath)));

        publicPem = publicPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] publicBytes = Base64.getDecoder().decode(publicPem);

        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(publicBytes);
        longTermPublicKey = kf.generatePublic(pubSpec);

        System.out.println("[Interceptor] Long-term ECDSA keys loaded");
    }

    public void onHandshake(BufferedReader input, PrintWriter output, PublicKey otherLongTermPublicKey) throws IOException {
        try {
            System.out.println("[Interceptor] Starting ECDH handshake");
            // Génération paire ECDH éphémère
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1"); // courbe recommandée 256 bits
            kpg.initialize(ecSpec);

            KeyPair keyPair = kpg.generateKeyPair();

            // --- SIGNATURE DE LA CLE ECDH ---
            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
            ecdsaSign.initSign(longTermPrivateKey); // clé ECDSA long terme
            ecdsaSign.update(keyPair.getPublic().getEncoded());
            byte[] signatureBytes = ecdsaSign.sign();

            // Encode Base64
            String myPublicKeyB64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String signatureB64 = Base64.getEncoder().encodeToString(signatureBytes);

            // Envoi : clé publique + signature
            output.println(myPublicKeyB64);
            output.println(signatureB64);

            // Lecture clé publique distante
            String otherPublicKeyB64 = input.readLine();
            String otherSignatureB64 = input.readLine(); // nouveau nom pour éviter conflit
            byte[] otherKeyBytes = Base64.getDecoder().decode(otherPublicKeyB64);
            byte[] otherSignatureBytes = Base64.getDecoder().decode(otherSignatureB64);

            // Création objet PublicKey ECDH
            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(otherKeyBytes);
            PublicKey otherPublicKey = kf.generatePublic(keySpec);

            // --- Vérification de la signature ECDSA ---
            Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
            ecdsaVerify.initVerify(otherLongTermPublicKey); // <-- utilise la clé publique longue durée passée en paramètre
            ecdsaVerify.update(otherPublicKey.getEncoded());

            if (!ecdsaVerify.verify(otherSignatureBytes)) {
                throw new SecurityException("[Interceptor] Signature ECDSA invalide ! Handshake interrompu");
            } else {
                System.out.println("[Interceptor] Signature ECDSA de la clé ECDH vérifiée");
            }

            // Calcul secret partagé
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(keyPair.getPrivate());
            ka.doPhase(otherPublicKey, true);
            byte[] sharedSecret = ka.generateSecret();

            // Dérivation clé AES-128 via SHA-256
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] derivedKey = sha.digest(sharedSecret);

            aesKey = new SecretKeySpec(
                    Arrays.copyOf(derivedKey, 16), // 128 bits
                    "AES"
            );

            System.out.println("[Interceptor] AES session key established");

        } catch (Exception e) {
            throw new IOException("ECDH handshake failed", e);
        }
    }


    public String beforeSend(String plainText) {
        try {
           System.out.println("[Interceptor] Encrypting message: " + plainText);
			return processAESGCM(plainText, aesKey, true);//chiffrer
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String afterReceive(String encryptedText) {
        try {
            System.out.println("[Interceptor] Decrypting message...");
			return processAESGCM(encryptedText, aesKey, false);//dechiffrer
        } catch (Exception e) {
            return "[Decryption failed: " + e.getMessage() + "]";
        }
    }
	
	 /**
     * ROT13 encoding/decoding (Caesar cipher with shift of 13)
     * This is NOT secure and is only for initial demonstration.
     * You will replace this with proper cryptographic algorithms.
     *
     * @param text The text to encode/decode
     * @return The ROT13 transformed text
     */
    private String processAESGCM(String input, SecretKey key, boolean encrypt) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            if (encrypt) {
                byte[] iv = new byte[12]; // 96 bits, recommandé pour GCM
                SecureRandom random = new SecureRandom();
                random.nextBytes(iv);
                GCMParameterSpec spec = new GCMParameterSpec(128, iv); // tag 128 bits
                cipher.init(Cipher.ENCRYPT_MODE, key, spec);

                byte[] cipherText = cipher.doFinal(input.getBytes("UTF-8"));

                // Concaténation IV + ciphertext
                byte[] result = new byte[iv.length + cipherText.length];
                System.arraycopy(iv, 0, result, 0, iv.length);
                System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);

                return Base64.getEncoder().encodeToString(result); // Base64 uniquement pour l'envoi
            } else {
                byte[] combined = Base64.getDecoder().decode(input);
                byte[] ivExtracted = Arrays.copyOfRange(combined, 0, 12);
                byte[] cipherText = Arrays.copyOfRange(combined, 12, combined.length);

                GCMParameterSpec specDec = new GCMParameterSpec(128, ivExtracted);
                cipher.init(Cipher.DECRYPT_MODE, key, specDec);
                byte[] plainTextBytes = cipher.doFinal(cipherText);

                return new String(plainTextBytes, "UTF-8"); // Retourne le texte clair
            }

        } catch (Exception e) {
            throw new RuntimeException("AES-GCM processing failed: " + e.getMessage(), e);
        }
    }

}