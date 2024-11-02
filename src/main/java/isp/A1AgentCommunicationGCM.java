package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import javax.crypto.spec.GCMParameterSpec;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using a
 * AES in GCM. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // Send 10 messages
                for (int i = 0; i < 10; i++) {
                    final String text = String.format("Message %d from Alice to Bob, kisses", i);
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    
                    // Setup encryption cipher
                    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = cipher.doFinal(pt);
                    
                    // Send IV and ciphertext
                    send("bob", cipher.getIV());
                    send("bob", ct);
                    
                    // Print sent message
                    System.out.printf("Alice sent: %s%n", text);
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive 10 messages
                for (int i = 0; i < 10; i++) {
                    // Receive IV and ciphertext
                    final byte[] iv = receive("alice");
                    final byte[] ct = receive("alice");
                    
                    // Setup decryption cipher
                    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
                    final byte[] pt = cipher.doFinal(ct);
                    
                    // Print received message
                    System.out.printf("Bob received: %s%n", new String(pt, StandardCharsets.UTF_8));
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
