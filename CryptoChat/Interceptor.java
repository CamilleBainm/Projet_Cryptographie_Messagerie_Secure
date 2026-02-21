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

    //Constructeur qui dérive la clé AES à partir du mot de passe fourni par l'utilisateur
    public Interceptor(String password) throws Exception {
        // Dérivation de la clé AES 128 bits via SHA-256
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha.digest(password.getBytes("UTF-8"));
        keyBytes = Arrays.copyOf(keyBytes, 16); // AES 128 bits
        aesKey = new SecretKeySpec(keyBytes, "AES");//Clé dérivé depuis le mot de passe

        System.out.println("[Interceptor] AES key derived from password.");
    }

    public Interceptor() {
        
    }

    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        try {
            System.out.println("[Interceptor] Starting handshake");

            

            System.out.println("[Interceptor] Handshake complete!");
        } catch (Exception e) {
            throw new IOException("Handshake failed", e);
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
            byte[] iv = new byte[12]; // 96 bits, recommandé pour GCM
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            GCMParameterSpec spec = new GCMParameterSpec(128, iv); // tag 128 bits

            byte[] result;

            if (encrypt) {
                cipher.init(Cipher.ENCRYPT_MODE, key, spec);
                byte[] cipherText = cipher.doFinal(input.getBytes("UTF-8"));

                // Concaténation IV + ciphertext + tag
                result = new byte[iv.length + cipherText.length];
                System.arraycopy(iv, 0, result, 0, iv.length);
                System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);

            } else {
                byte[] combined = Base64.getDecoder().decode(input);
                byte[] ivExtracted = Arrays.copyOfRange(combined, 0, 12);
                byte[] cipherText = Arrays.copyOfRange(combined, 12, combined.length);

                GCMParameterSpec specDec = new GCMParameterSpec(128, ivExtracted);
                cipher.init(Cipher.DECRYPT_MODE, key, specDec);
                result = cipher.doFinal(cipherText); // exception si modifié
            }

            return Base64.getEncoder().encodeToString(result);

        } catch (Exception e) {
            throw new RuntimeException("AES-GCM processing failed: " + e.getMessage(), e);
        }
    }
}


