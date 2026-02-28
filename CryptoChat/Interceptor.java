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


    public Interceptor() {
        
    }

    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        try {
            System.out.println("[Interceptor] Starting ECDH handshake");

            //Génération paire ECDH éphémère
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1"); // courbe recommandée 256 bits
            kpg.initialize(ecSpec);

            KeyPair keyPair = kpg.generateKeyPair();

            //Envoi clé publique encodée Base64
            String myPublicKeyB64 = Base64.getEncoder()
                    .encodeToString(keyPair.getPublic().getEncoded());
            output.println(myPublicKeyB64);

            //Réception clé publique distante
            String otherPublicKeyB64 = input.readLine();
            byte[] otherKeyBytes = Base64.getDecoder().decode(otherPublicKeyB64);

            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(otherKeyBytes);
            PublicKey otherPublicKey = kf.generatePublic(keySpec);

            System.out.println("Received key length (Base64): " + otherPublicKeyB64.length());
            System.out.println("Received key: " + otherPublicKeyB64);


            //Calcul secret partagé
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(keyPair.getPrivate());
            ka.doPhase(otherPublicKey, true);
            byte[] sharedSecret = ka.generateSecret();

            //Dérivation clé AES-128 via SHA-256
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


