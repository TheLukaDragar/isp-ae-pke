package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import java.security.SecureRandom;
import java.security.Key;
import javax.crypto.spec.GCMParameterSpec;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.KeyGenerator;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * TASK:
 * We want to send a large chunk of data from Alice to Bob while maintaining its integrity and considering
 * the limitations of communication channels -- we have three such channels:
 * - Alice to Bob: an insecure channel, but has high bandwidth and can thus transfer large files
 * - Alice to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * - Bob to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * <p>
 * The plan is to make use of the public-space technique:
 * - Alice creates the data and computes its digest
 * - Alice sends the data to Bob, and sends the encrypted digest to Public Space
 * - Channel between Alice and Public space is secured with ChaCha20-Poly1305 (Alice and Public space share
 * a ChaCha20 key)
 * - Public space forwards the digest to Bob
 * - The channel between Public Space and Bob is secured but with AES in GCM mode (Bob and Public space share
 * an AES key)
 * - Bob receives the data from Alice and the digest from Public space
 * - Bob computes the digest over the received data and compares it to the received digest
 * <p>
 * Further instructions are given below.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AgentCommunicationPublicSpace {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        // Create keys
        final SecretKey chacha20Key = KeyGenerator.getInstance("ChaCha20").generateKey();
        final SecretKey aesKey = KeyGenerator.getInstance("AES").generateKey();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // Generate and send data
                final byte[] data = new byte[200 * 1024 * 1024];
                new SecureRandom().nextBytes(data);
                send("bob", data);

                // Compute digest
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(data);

                // Encrypt digest with ChaCha20-Poly1305
                Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
                cipher.init(Cipher.ENCRYPT_MODE, chacha20Key);
                byte[] encryptedHash = cipher.doFinal(hash);
                
                // Send IV and encrypted hash
                send("public-space", cipher.getIV());
                send("public-space", encryptedHash);
            }
        });

        env.add(new Agent("public-space") {
            @Override
            public void task() throws Exception {
                // Receive and decrypt from Alice
                byte[] iv = receive("alice");
                byte[] encryptedHash = receive("alice");
                
                Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
                cipher.init(Cipher.DECRYPT_MODE, chacha20Key, new IvParameterSpec(iv));
                byte[] hash = cipher.doFinal(encryptedHash);

                // Encrypt with AES-GCM for Bob
                Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
                aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
                byte[] reEncryptedHash = aesCipher.doFinal(hash);
                
                // Send to Bob
                send("bob", aesCipher.getIV());
                send("bob", reEncryptedHash);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive and hash data from Alice
                byte[] data = receive("alice");
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] computedHash = digest.digest(data);

                // Receive and decrypt hash from public-space
                byte[] iv = receive("public-space");
                byte[] encryptedHash = receive("public-space");
                
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec specs = new GCMParameterSpec(128, iv);
                cipher.init(Cipher.DECRYPT_MODE, aesKey, specs);
                byte[] receivedHash = cipher.doFinal(encryptedHash);

                // Verify
                System.out.println(Arrays.equals(computedHash, receivedHash) ? 
                    "data valid" : "data invalid");
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "public-space");
        env.connect("public-space", "bob");
        env.start();
    }
}
