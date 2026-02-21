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
			return processAES(plainText, aesKey, true);//chiffrer
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String afterReceive(String encryptedText) {
        try {
            System.out.println("[Interceptor] Decrypting message...");
			return processAES(encryptedText, aesKey, false);//dechiffrer
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
    private String rot13(String text) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (c >= 'a' && c <= 'z') {
                result.append((char) ((c - 'a' + 13) % 26 + 'a'));
            } else if (c >= 'A' && c <= 'Z') {
                result.append((char) ((c - 'A' + 13) % 26 + 'A'));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
    private String processAES(String input, SecretKey key, boolean encrypt) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

            if (encrypt) {
                // Générer IV aléatoire
                byte[] iv = new byte[16];
                SecureRandom random = new SecureRandom();
                random.nextBytes(iv);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);

                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

                byte[] cipherText = cipher.doFinal(input.getBytes("UTF-8"));

                // Concaténer IV + ciphertext
                byte[] combined = new byte[iv.length + cipherText.length];
                System.arraycopy(iv, 0, combined, 0, iv.length);
                System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);

                return Base64.getEncoder().encodeToString(combined);

            } else {
                byte[] combined = Base64.getDecoder().decode(input);

                // Extraire IV
                byte[] iv = Arrays.copyOfRange(combined, 0, 16);
                byte[] cipherText = Arrays.copyOfRange(combined, 16, combined.length);

                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

                byte[] plainText = cipher.doFinal(cipherText);

                return new String(plainText, "UTF-8");
            }

        } catch (Exception e) {
            throw new RuntimeException("AES processing failed", e);
        }
    }

}

