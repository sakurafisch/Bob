package Bob;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.oracle.truffle.api.library.Message;

public class Client {
    private DatagramSocket datagramSocket;
    private InetAddress address;

    private byte[] buffer;

    public static void main(String[] args) {
        System.out.println();
        try {
            String s = sha1("pa23word");
            System.out.println(s);
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
        } catch (CloneNotSupportedException cnse) {
            cnse.printStackTrace();
        }
        // Client client = new Client();
        // String rsp = client.sendEcho("end");
        // System.out.println("rsp is: " + rsp);
        // client.close();
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

    public String sendEcho(String msg) {
        buffer = msg.getBytes();
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, 4445);
        try {
            datagramSocket.send(packet);
        } catch (IOException e) {
            e.printStackTrace();
        }
        packet = new DatagramPacket(buffer, buffer.length);
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

    public final static String sha1(String input_content) throws NoSuchAlgorithmException, CloneNotSupportedException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
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
}
