package com.winnerwinter;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.util.Base64;

public class Client {
    private DatagramSocket datagramSocket;
    private InetAddress address;
    private byte[] buffer;

    public static void main(String[] args) {
        Client client = new Client();
        try {
            client.interact();
        } catch (CloneNotSupportedException cnse) {
            cnse.printStackTrace();
            client.close();
        } catch (Exception e) {
            e.printStackTrace();
            client.close();
        }
        client.close();
    }

    public Client() {
        try {
            datagramSocket = new DatagramSocket();
        } catch (SocketException e) {
            e.printStackTrace();
        }
        try {
            address = InetAddress.getByName("localhost");
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }

    public void interact() throws Exception {
        System.out.println();
        String username, password;
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter the username: ");
        username = scanner.nextLine();
        System.out.println("Enter the password: ");
        password = scanner.nextLine();
        scanner.close();
        String rev = sendMsg(username + password);
        // System.out.println(rev);
        if (rev.equals("fail")) {
            System.out.println("username or password is invalid");
            throw new Exception("username or password is invalid");
        }
        System.out.println("username and password are correct");
        // System.out.println(rev);
        String[] revs =  rev.split("-----END PUBLIC KEY-----");
        String pk = revs[0].concat("-----END PUBLIC KEY-----").trim();
        pk = pk + '\n';

        String pk_hashed;
        try {
            pk_hashed = sha1(pk);
        } catch (CloneNotSupportedException cnse) {
            cnse.printStackTrace();
            throw new Exception("Fail to execute sha1()");
        }
        System.out.println();
        String NA = revs[1].trim();
        System.out.println("NA is " + NA);
        String pk_loaded = Files.readString(Path.of("./pk.crt.hashed.txt"));
        if (!pk_loaded.equals(pk_hashed)) {
            System.out.println("pk_hashed: " + pk_hashed);
            System.out.println("pk_loaded: " + pk_loaded);
            PrintWriter out = new PrintWriter("fail_pk.txt");
            out.println(pk);
            out.close();
            throw new Exception("This may not Alice");

        }
        System.out.println("Alice's public key is verified");

        String OTP;
        try {
            OTP = sha1(pk_hashed + NA);
        } catch (CloneNotSupportedException cnse) {
            cnse.printStackTrace();
            throw new Exception("Fail to execute sha1()");
        }
        String ciphertext = rsa_encrypt(pk, OTP);
        String result = sendMsg(ciphertext);
        if (result.equalsIgnoreCase("success")) {
            System.out.println("Successfully interacted with Host Alice!");
        } else {
            System.out.println("Fail to interacted with Host Alice");
        }
    }

    public String sendMsg(String msg) {
        buffer = msg.getBytes();
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, 4445);
        try {
            datagramSocket.send(packet);
        } catch (IOException e) {
            e.printStackTrace();
        }
        buffer = new byte[65535];
        packet = new DatagramPacket(buffer, buffer.length, address, 4445);
        try {
            datagramSocket.receive(packet);
        } catch (IOException e) {
            e.printStackTrace();
        }
        String received = new String(packet.getData(), 0, packet.getLength());
        return received;
    }

    public void close() {
        datagramSocket.close();
    }

    public final static String sha1(String input_content) throws CloneNotSupportedException {
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
            System.exit(1);
            return "";
        }
        messageDigest.update(input_content.getBytes());
        byte[] hashed_content = messageDigest.digest();
        return toHexString(hashed_content);
    }

    public final static String toHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
    
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xFF & bytes[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
    
        return hexString.toString();
    }

    private final static PublicKey getPublicKey(String pk) throws Exception {
        String pkPem = pk.replace("-----BEGIN PUBLIC KEY-----", "").replaceAll("\n", "").replace("-----END PUBLIC KEY-----", "").trim();
        byte[] keyBytes;
        keyBytes = Base64.getDecoder().decode(pkPem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    public final static String rsa_encrypt(String pk, String plaintext) throws Exception {
        System.out.println("RSA encrypting " + plaintext);
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(pk));
            byte[] enBytes = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(enBytes);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        throw new Exception("Fail to execute rsa_encrypt()");
    }
}
