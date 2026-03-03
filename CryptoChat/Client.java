import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;


public class Client {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 8888;

    private Socket socket;
    private BufferedReader input;
    private PrintWriter output;
    private Interceptor interceptor;
    private volatile boolean running;

    private PublicKey otherClientLongTermPublicKey;

    public Client(String privateKeyPath, String clientCertPath, String caCertPath) {
        this.interceptor = new Interceptor(privateKeyPath, clientCertPath, caCertPath);
        this.running = true;
    }
    
    private static PublicKey loadPublicKeyFromPEM(String path) throws Exception {
        String publicPem = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path)));
        publicPem = publicPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] publicBytes = Base64.getDecoder().decode(publicPem);
        KeyFactory kf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(publicBytes);
        return kf.generatePublic(pubSpec);
    }
    public static void main(String[] args) {
    if (args.length != 3) {
        System.out.println("Usage: java Client <privateKey.pem> <clientCert.pem> <caCert.pem>");
        return;
    }

    String privateKeyPath = args[0];
    String clientCertPath = args[1];
    String caCertPath = args[2];

        try {
            Client client = new Client(privateKeyPath, clientCertPath, caCertPath);
            client.start();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //This method is called when the client starts. It handles the connection to the server,
    public void start() {
        System.out.println("=== Crypto Chat Client ===");
        System.out.println("Connecting to server at " + SERVER_HOST + ":" + SERVER_PORT + "...");

        try {
            socket = new Socket(SERVER_HOST, SERVER_PORT);
            System.out.println("Connected to server successfully!\n");

            input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            output = new PrintWriter(socket.getOutputStream(), true);

            //Wait for server's READY signal (sent when both clients are connected)
            System.out.println("Waiting for other client to connect...");
            String readySignal = input.readLine();
            if (!"READY".equals(readySignal)) {
                throw new IOException("Expected READY signal, got: " + readySignal);
            }
            System.out.println("Both clients connected!\n");

            System.out.println("--- Handshake Phase ---");
            interceptor.onHandshake(input, output);
            System.out.println("--- Handshake Complete ---\n");

            System.out.println("Chat session started!");
            System.out.println("Type your messages and press Enter to send.");
            System.out.println("Type 'exit' to quit.\n");

            Thread receiverThread = new Thread(new MessageReceiver());
            receiverThread.start();

            handleUserInput();

        } catch (IOException e) {
            System.err.println("Connection error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            cleanup();
        }
    }

    //This method handles user input from the console, encrypts it using the interceptor, and sends it to the server.
    private void handleUserInput() {
        Scanner scanner = new Scanner(System.in);

        try {
            while (running) {
                String message = scanner.nextLine();

                if (message.equalsIgnoreCase("exit")) {
                    System.out.println("Disconnecting...");
                    running = false;
                    break;
                }

                if (message.trim().isEmpty()) {
                    continue;
                }

                String processedMessage = interceptor.beforeSend(message);
                output.println(processedMessage);
                System.out.println("You: " + message);
            }
        } finally {
            scanner.close();
        }
    }

    private void cleanup() {
        running = false;

        try {
            if (input != null) input.close();
            if (output != null) output.close();
            if (socket != null && !socket.isClosed()) socket.close();
        } catch (IOException e) {
            System.err.println("Error during cleanup: " + e.getMessage());
        }

        System.out.println("Disconnected from server.");
    }

    // This inner class continuously listens for messages from the server, decrypts them using the interceptor, and displays them to the user.
    private class MessageReceiver implements Runnable {
        @Override
        public void run() {
            try {
                String receivedMessage;

                while (running && (receivedMessage = input.readLine()) != null) {
                    String decryptedMessage = interceptor.afterReceive(receivedMessage);
                    System.out.println("Other: " + decryptedMessage);
                }

            } catch (IOException e) {
                if (running) {
                    System.err.println("Error receiving message: " + e.getMessage());
                }
            }
        }
    }
}