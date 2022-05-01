import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetAddress;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.net.Socket;
import java.io.ByteArrayOutputStream;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;


public class Client {
    private static final int PORT = 1337;
    private static final String SRVPUBKEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCDAZzhQdUIHkWLtDIe0rXONPYAwGY8WxiOqc7DAfJL/xoXQkYG0zep766kqkCHFOzuu5EKU2g03QbbWINgxGt6t2LM6ZyqoRJhM7g3mLxZ4TsH5hwElc6eq/KHGRuPE/f/eOmBWAVOVLgKdpHDZGzdA7MZjuvjYEgRhISr3/YKnQIDAQAB";
    private Socket clientSocket;
    private DataOutputStream out;
    private BufferedReader in;

    public void connect() throws IOException {
        //connect to server on locahost
        clientSocket = new Socket(InetAddress.getLoopbackAddress(), PORT);
        in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        out = new DataOutputStream(clientSocket.getOutputStream());
    }

    public void close() throws IOException {
        in.close();
        out.close();
        clientSocket.close();
    }

    public static String generateMessage(String s, String priv) throws Exception{
        String sign = RSAUtils.sign(s, RSAUtils.getPrivateKey(priv));
        return (sign + "\n" + s + "\n");
    }

    public static void main(String[] args) throws IOException {
        //create a client
        Client client = new Client();

        //generate key pair
        KeyPair kp;
        try{
            kp = RSAUtils.getKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        //get private and public keys as strings
        String priv = new String(Base64.getEncoder().encode(kp.getPrivate().getEncoded()), "UTF-8");
        String pub = new String(Base64.getEncoder().encode(kp.getPublic().getEncoded()), "UTF-8");

        //attempt connection
        try{
            //connect
            client.connect();
            System.out.println("Connected");

            // MESSAGE 1 ------------------------------------------------------------------------------

            //send initial message public key sign + \n + public key
            /**
            String sign_k_pub = RSAUtils.sign(pub, RSAUtils.getPrivateKey(priv));
            client.message(sign_k_pub + "\n" + pub);
             **/
            String m = generateMessage(pub,priv);
            client.out.writeBytes(m);
            System.out.println("Message 1 (public key) Sent");

            //interpret response
            String enc_AES = client.in.readLine();
            System.out.println("3" + enc_AES);
            //split to get tmp and ip
            String[] tmp = client.in.readLine().split(" ");
            String rand = tmp[0];
            String ip = tmp[1];
            //get the signiture
            String sign_AES_rand = client.in.readLine();

            //verify the signiture
            Boolean valid = RSAUtils.verify(enc_AES + rand, RSAUtils.getPublicKey(SRVPUBKEY), sign_AES_rand);
            //if not valid, close the connection, print msg
            if(!valid){
                client.close();
                System.out.println("ERROR VERIFYING AES KEY SIGNATURE");
                return;
            }
            System.out.println("Signature 1 (AES) Verified");

            //decrypt AES key
            String AES = RSAUtils.decryptByPrivateKey(enc_AES, RSAUtils.getPrivateKey(priv));

            //encrypt random string with AES
            String enc_rand = RSAUtils.aesEncrypt(rand, AES);

            //MESSAGE 2 -------------------------------------------------------------------------------

            //message enc_rand sign + \n + enc_rand
            m = generateMessage(enc_rand,priv);
            client.out.writeBytes(m);

            System.out.println("Message 2 (encrypted random string) Sent");

            //interpret response
            String ok = client.in.readLine();
            String sign_ok = client.in.readLine();
            ip = client.in.readLine();

            //verify signiture  
            valid = RSAUtils.verify(ok, RSAUtils.getPublicKey(SRVPUBKEY), sign_ok);
            //if not valid, close the connection, print msg
            if(!valid){
                client.close();
                System.out.println("ERROR VERIFYING OK MSG SIGNATURE");
                return;
            }

            //close the connection
            client.close();
            System.out.println("Signature 2 (OK.) Verified");
            System.out.println("Finished, Closing Connection");

        }
        catch(IOException e){
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
