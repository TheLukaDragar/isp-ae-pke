package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;

public class A3AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // Create message and convert to bytes
                String message = "I would like to keep this text confidential, Bob. Kind regards, Alice.";
                byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                
                // Create RSA cipher for encryption
                Cipher rsaEnc = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                
                // Encrypt and send the message
                byte[] ct = rsaEnc.doFinal(pt);
                send("bob", ct);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive the encrypted message
                byte[] ct = receive("alice");
                
                // Create RSA cipher for decryption
                Cipher rsaDec = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                
                // Decrypt and print the message
                byte[] pt = rsaDec.doFinal(ct);
                String message = new String(pt, StandardCharsets.UTF_8);
                print("Received message: " + message);
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
