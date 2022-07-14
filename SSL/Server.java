import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;

public class Server {
    public final static byte client_hello = (byte) 0x80;
    public final static byte server_hello = (byte) 0x81;
    public final static byte server_certificate = (byte) 0x82;
    public final static byte client_certificate = (byte) 0x83;
    public final static byte certificate_verify = (byte) 0x84;
    public final static byte client_key_exchange = (byte) 0x85;
    public final static byte server_finished = (byte) 0x86;
    public final static byte client_finished = (byte) 0x87;
    public final static byte error_message = (byte) 0x88;
    public final static byte application_data = (byte) 0x89;

    static boolean handshake = false;
    static boolean connection = true;
    static byte[] clienthello = new byte[32];
    static byte[] serverhello = new byte[32];
    static byte[] Seq = new byte[16];
    static int flag = 3;
    static byte error;
    static boolean jump = false;
    static RSAPublicKey server_PublicKey;
    static RSAPrivateKey server_PrivateKey;
    static String server_publicKeyString, server_privateKeyString;
    static byte[] spublicKey, sprivateKey;
    byte[] cipherSuite = new byte[]{(byte) 0x01, (byte) 0x00};
    byte[] c_certificate;
    byte[] master_secret = new byte[48];
    byte[] encryptedSharedSecret;
    byte[] sign;
    byte[] SKey = new byte[16];
    byte[] MKey = new byte[16];
    static int error_num=0;

    public static void main(String[] args) throws Exception {
        //建立连接
        DatagramSocket serverSocket = new DatagramSocket(4321);
        DatagramPacket receivePacket;
        Server server = new Server();

        while (true) {
            while (!handshake) {
                //接收数据包
                byte[] ReceiveData = new byte[200];
                receivePacket = new DatagramPacket(ReceiveData, ReceiveData.length);
                serverSocket.receive(receivePacket);

                if (ReceiveData[0] == client_hello) {
                    server.ServerHello(ReceiveData, serverSocket, receivePacket);
                    System.arraycopy(clienthello, 0, Seq, 0, 8);
                    System.arraycopy(serverhello, 0, Seq, 8, 8);
                } else if (ReceiveData[0] == client_certificate && connection) {
                    server.save_c_certificate(ReceiveData);
                } else if (ReceiveData[0] == certificate_verify && connection) {
                    server.Verify(serverSocket, receivePacket, ReceiveData);
                } else if (ReceiveData[0] == client_key_exchange && connection) {
                    server.save_master_secret(ReceiveData);
                    server.ServerFinished(serverSocket, receivePacket);
                } else if (ReceiveData[0] == client_finished && connection) {
                    server.CFinished_Verify(serverSocket, receivePacket, ReceiveData);
                } else if (ReceiveData[0] == error_message) {
                    connection = false;
                    error = ReceiveData[3];
                    break;
                }else if(error_num!=0){
                    error_num=0;
                    break;
                }
            }

            if (!connection) {
                switch ((error)) {
                    case 0x01:
                        jump = true;
                        System.out.println("ClientCiperSuiteError!");
                        break;
                    case 0x02:
                        jump = true;
                        System.out.println("ServerCiperSuiteError!");
                        break;
                    case 0x03:
                        jump = true;
                        System.out.println("ClientCertificateError!");
                        break;
                    case 0x04:
                        jump = true;
                        System.out.println("ServerCertificateError!");
                        break;
                    case 0x05:
                        jump = true;
                        System.out.println("ClientHandshakeError!");
                        break;
                    case 0x08:
                        jump = true;
                        System.out.println("ServerHandshakeError!");
                        break;
                    default:
                        jump = true;
                        System.out.println("UnknownError!");
                        break;
                }
            }

            if (jump)
                break;

            while (handshake) {
                if (flag != 0) {
                    byte[] ReceiveData = new byte[200];
                    receivePacket = new DatagramPacket(ReceiveData, ReceiveData.length);
                    serverSocket.receive(receivePacket);
                    server.Receive(ReceiveData, serverSocket, receivePacket);
                    if (flag == 3)
                        server.Send(serverSocket, receivePacket);
                    else continue;
                } else {
                    handshake = false;
                    flag = 3;
                    break;
                }
            }
        }
    }

    //转为32字节的十六进制数
    private static String convertBytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte temp : bytes) {
            result.append(String.format("%02x", temp));
        }
        return result.toString();
    }

    //获取RSA公私钥对
    public static void genKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        server_PublicKey = (RSAPublicKey) keyPair.getPublic();
        server_PrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        server_publicKeyString = encryptBASE64(server_PublicKey.getEncoded());
        server_privateKeyString = encryptBASE64(server_PrivateKey.getEncoded());
        spublicKey = decryptBASE64(server_publicKeyString);
        sprivateKey = decryptBASE64(server_privateKeyString);
    }

    //编码返回字符串
    public static String encryptBASE64(byte[] key) throws Exception {
        return (new BASE64Encoder()).encodeBuffer(key);
    }

    //解码返回byte
    public static byte[] decryptBASE64(String key) throws Exception {
        return (new BASE64Decoder()).decodeBuffer(key);
    }

    public static byte[] HMAC(byte[] key, byte[] content) throws Exception {
        Mac hmacSha256 = Mac.getInstance("HmacSHA256");
        hmacSha256.init(new SecretKeySpec(key, 0, key.length, "HmacSHA256"));
        return hmacSha256.doFinal(content);
    }

    public void Receive(byte[] Receivedata, DatagramSocket serverSocket, DatagramPacket receivePacket) throws Exception {
        if (Receivedata[0] == error_message) {
            flag--;
        } else {
            byte[] encryptedData = new byte[16];
            System.arraycopy(Receivedata, 3, encryptedData, 0, 16);

            System.out.println("Seq: " + convertBytesToHex(Seq));
            Seq[Seq.length - 1] = (byte) (Seq[Seq.length - 1] + 1);

            byte[] Mdata = new byte[32];
            System.arraycopy(Seq, 0, Mdata, 0, 16);
            System.arraycopy(encryptedData, 0, Mdata, 16, 16);

            byte[] iv = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
            IvParameterSpec ivp = new IvParameterSpec(iv);
            SecretKeySpec skeySpec = new SecretKeySpec(MKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivp);
            byte[] E_Mdata = cipher.doFinal(Mdata);
            byte[] cl = new byte[8];
            byte[] cr = new byte[8];
            System.arraycopy(E_Mdata, E_Mdata.length - 16, cl, 0, 8);
            System.arraycopy(E_Mdata, E_Mdata.length - 8, cr, 0, 8);

            byte[] dataMAC = new byte[8];
            for (int i = 0; i < 8; i++) {
                dataMAC[i] = (byte) (cl[i] ^ cr[i]);
            }

            byte[] rev_dataMAC = new byte[8];
            //System.arraycopy(Receivedata,3+encryptedData.length,rev_dataMAC,0,8);

            if (!Arrays.equals(dataMAC, rev_dataMAC)) {
                flag--;
                System.out.println("RecordError!");
                byte[] RE = new byte[]{(byte) 0x09};
                Message m = new Message(error_message, (short) RE.length, RE);
                byte[] SendData = m.Data();
                InetAddress clientAddress = receivePacket.getAddress();
                int clientPort = receivePacket.getPort();
                DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, clientAddress, clientPort);
                serverSocket.send(sendPacket);
                System.out.println("ERROR: " + convertBytesToHex(SendData));
            } else {
                iv = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
                ivp = new IvParameterSpec(iv);
                skeySpec = new SecretKeySpec(SKey, "AES");
                cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivp);
                String message = new String(cipher.doFinal(encryptedData), 1, cipher.doFinal(encryptedData).length - 1);
                System.out.println("消息已正确接收: " + message);
            }
        }
    }

    public void Send(DatagramSocket serverSocket, DatagramPacket receivePacket) throws Exception {
        byte[] data;
        Scanner scan = new Scanner(System.in);
        data = scan.nextLine().getBytes();
        byte[] l = new byte[]{(byte) data.length};
        byte[] D = new byte[l.length + data.length];
        System.arraycopy(l, 0, D, 0, l.length);
        System.arraycopy(data, 0, D, l.length, data.length);

        byte[] iv = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        IvParameterSpec ivp = new IvParameterSpec(iv);
        SecretKeySpec skeySpec = new SecretKeySpec(SKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivp);
        byte[] encryptedData = cipher.doFinal(D);

        System.out.println("Seq: " + convertBytesToHex(Seq));
        Seq[Seq.length - 1] = (byte) (Seq[Seq.length - 1] + 1);

        byte[] Mdata = new byte[32];
        System.arraycopy(Seq, 0, Mdata, 0, 16);
        System.arraycopy(encryptedData, 0, Mdata, 16, 16);

        iv = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        ivp = new IvParameterSpec(iv);
        skeySpec = new SecretKeySpec(MKey, "AES");
        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivp);
        byte[] E_Mdata = cipher.doFinal(Mdata);
        byte[] cl = new byte[8];
        byte[] cr = new byte[8];
        System.arraycopy(E_Mdata, E_Mdata.length - 16, cl, 0, 8);
        System.arraycopy(E_Mdata, E_Mdata.length - 8, cr, 0, 8);

        byte[] dataMAC = new byte[8];
        for (int i = 0; i < 8; i++) {
            dataMAC[i] = (byte) (cl[i] ^ cr[i]);
        }

        Record record = new Record(application_data, (short) (encryptedData.length + dataMAC.length), encryptedData, dataMAC);
        byte[] SendData = record.Data();
        InetAddress clientAddress = receivePacket.getAddress();
        int clientPort = receivePacket.getPort();
        DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, clientAddress, clientPort);
        serverSocket.send(sendPacket);
        //System.out.println("消息已发送: " + convertBytesToHex(SendData));
        System.out.println("消息已发送!");
    }

    public void ServerHello(byte[] data, DatagramSocket serverSocket, DatagramPacket receivePacket) throws Exception {
        if (data[35] == cipherSuite[0] && data[36] == cipherSuite[1]) {
            System.arraycopy(data, 3, clienthello, 0, 32);
            byte[] sh_msg = new byte[34];

            new SecureRandom().nextBytes(serverhello);
            System.arraycopy(serverhello, 0, sh_msg, 0, serverhello.length);
            System.arraycopy(cipherSuite, 0, sh_msg, 32, cipherSuite.length);

            Message m = new Message(server_hello, (short) sh_msg.length, sh_msg);
            byte[] SendData = m.Data();
            InetAddress clientAddress = receivePacket.getAddress();
            int clientPort = receivePacket.getPort();
            DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, clientAddress, clientPort);
            serverSocket.send(sendPacket);
            //System.out.println("ServerHello: " + convertBytesToHex(SendData));
            System.out.println("ServerHello");

            ServerCertificate(serverSocket, receivePacket);
        } else {
            //System.out.println("ClientCiperSuiteError!");
            connection = false;
            byte[] CCSE = new byte[]{(byte) 0x01};
            error=CCSE[0];
            error_num++;
            Message m = new Message(error_message, (short) CCSE.length, CCSE);
            byte[] SendData = m.Data();
            InetAddress clientAddress = receivePacket.getAddress();
            int clientPort = receivePacket.getPort();
            DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, clientAddress, clientPort);
            serverSocket.send(sendPacket);
            System.out.println("ERROR: " + convertBytesToHex(SendData));
        }
    }

    public void ServerCertificate(DatagramSocket serverSocket, DatagramPacket receivePacket) throws Exception {
        genKeyPair();

        Message m = new Message(server_certificate, (short) spublicKey.length, spublicKey);
        byte[] SendData = m.Data();
        InetAddress clientAddress = receivePacket.getAddress();
        int clientPort = receivePacket.getPort();
        DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, clientAddress, clientPort);
        serverSocket.send(sendPacket);
        //System.out.println("ServerCertificate: " + convertBytesToHex(SendData));
        System.out.println("ServerCertificate");
    }

    public void save_c_certificate(byte[] ReceiveData) {
        c_certificate = new byte[162];
        System.arraycopy(ReceiveData, 3, c_certificate, 0, 162);
    }

    public void Verify(DatagramSocket serverSocket, DatagramPacket receivePacket, byte[] ReceiveData) throws Exception {
        sign = new byte[128];
        byte[] data = new byte[clienthello.length + serverhello.length + spublicKey.length];
        System.arraycopy(clienthello, 0, data, 0, clienthello.length);
        System.arraycopy(serverhello, 0, data, clienthello.length, serverhello.length);
        System.arraycopy(spublicKey, 0, data, (clienthello.length + serverhello.length), spublicKey.length);

        System.arraycopy(ReceiveData, 3, sign, 0, 128);

        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(c_certificate);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        Signature signature = Signature.getInstance("Sha1withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        boolean verify = signature.verify(sign);
        System.out.println("Verify the signature: " + verify);

        if (!verify) {
            //System.out.println("ClientCertificateError!");
            connection = false;
            byte[] CCE = new byte[]{(byte) 0x03};
            error=CCE[0] ;
            error_num++;
            Message m = new Message(error_message, (short) CCE.length, CCE);
            byte[] SendData = m.Data();
            InetAddress clientAddress = receivePacket.getAddress();
            int clientPort = receivePacket.getPort();
            DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, clientAddress, clientPort);
            serverSocket.send(sendPacket);
            System.out.println("ERROR: " + convertBytesToHex(SendData));
        }
    }

    public void save_master_secret(byte[] ReceiveData) throws Exception {
        encryptedSharedSecret = new byte[128];
        System.arraycopy(ReceiveData, 3, encryptedSharedSecret, 0, 128);

        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(sprivateKey));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        master_secret = cipher.doFinal(encryptedSharedSecret);
        //System.out.println("master_secret: " + convertBytesToHex(master_secret));
    }

    public void ServerFinished(DatagramSocket serverSocket, DatagramPacket receivePacket) throws Exception {
        byte[] message_MAC;
        byte[] handshake_messages = new byte[384];
        System.arraycopy(clienthello, 0, handshake_messages, 0, clienthello.length);
        System.arraycopy(serverhello, 0, handshake_messages, clienthello.length, serverhello.length);
        int length1 = clienthello.length + serverhello.length;

        StringBuilder s = new StringBuilder();
        MessageDigest object = MessageDigest.getInstance("SHA-256");
        byte[] hash_sc = object.digest(spublicKey);
        byte[] hash_cc = object.digest(c_certificate);

        System.arraycopy(hash_sc, 0, handshake_messages, length1, hash_sc.length);
        System.arraycopy(hash_cc, 0, handshake_messages, length1 + hash_sc.length, hash_cc.length);
        int length2 = length1 + hash_sc.length + hash_cc.length;

        System.arraycopy(sign, 0, handshake_messages, length2, sign.length);
        System.arraycopy(encryptedSharedSecret, 0, handshake_messages, length2 + sign.length, encryptedSharedSecret.length);

        byte[] msg = new byte[38];
        byte[] Finish_label = ("SERVER").getBytes();
        System.arraycopy(Finish_label, 0, msg, 0, Finish_label.length);
        System.arraycopy(object.digest(handshake_messages), 0, msg, Finish_label.length, object.digest(handshake_messages).length);

        message_MAC = HMAC(master_secret, msg);

        Message m = new Message(server_finished, (short) message_MAC.length, message_MAC);
        byte[] SendData = m.Data();
        InetAddress clientAddress = receivePacket.getAddress();
        int clientPort = receivePacket.getPort();
        DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, clientAddress, clientPort);
        serverSocket.send(sendPacket);
        //System.out.println("ServerFinished: " + convertBytesToHex(SendData));
        System.out.println("ServerFinished");
    }

    public void CFinished_Verify(DatagramSocket serverSocket, DatagramPacket receivePacket, byte[] ReceiveData) throws Exception {
        byte[] CF = new byte[32];
        System.arraycopy(ReceiveData, 3, CF, 0, 32);
        byte[] message_MAC;
        byte[] handshake_messages = new byte[384];
        System.arraycopy(clienthello, 0, handshake_messages, 0, clienthello.length);
        System.arraycopy(serverhello, 0, handshake_messages, clienthello.length, serverhello.length);
        int length1 = clienthello.length + serverhello.length;

        StringBuilder s = new StringBuilder();
        MessageDigest object = MessageDigest.getInstance("SHA-256");
        byte[] hash_sc = object.digest(spublicKey);
        byte[] hash_cc = object.digest(c_certificate);

        System.arraycopy(hash_sc, 0, handshake_messages, length1, hash_sc.length);
        System.arraycopy(hash_cc, 0, handshake_messages, length1 + hash_sc.length, hash_cc.length);
        int length2 = length1 + hash_sc.length + hash_cc.length;

        System.arraycopy(sign, 0, handshake_messages, length2, sign.length);
        System.arraycopy(encryptedSharedSecret, 0, handshake_messages, length2 + sign.length, encryptedSharedSecret.length);

        byte[] msg = new byte[38];
        byte[] Finish_label = ("CLIENT").getBytes();
        System.arraycopy(Finish_label, 0, msg, 0, Finish_label.length);
        System.arraycopy(object.digest(handshake_messages), 0, msg, Finish_label.length, object.digest(handshake_messages).length);

        message_MAC = HMAC(master_secret, msg);

        if (!Arrays.equals(message_MAC, CF)) {
            //System.out.println("ClientHandshakeError!");
            connection = false;
            byte[] CHE = new byte[]{(byte) 0x05};
            error=CHE[0];
            error_num++;
            Message m = new Message(error_message, (short) CHE.length, CHE);
            byte[] SendData = m.Data();
            InetAddress clientAddress = receivePacket.getAddress();
            int clientPort = receivePacket.getPort();
            DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, clientAddress, clientPort);
            serverSocket.send(sendPacket);
            System.out.println("ERROR: " + convertBytesToHex(SendData));
        } else {
            System.out.println("ClientFinished is true!");
            byte[] X;
            byte[] msg2 = new byte[67];
            byte[] key_label = ("KEY").getBytes();
            System.arraycopy(key_label, 0, msg2, 0, key_label.length);
            System.arraycopy(clienthello, 0, msg2, key_label.length, clienthello.length);
            System.arraycopy(serverhello, 0, msg2, key_label.length + clienthello.length, serverhello.length);
            X = HMAC(master_secret, msg2);

            System.arraycopy(X, 0, SKey, 0, 16);
            System.arraycopy(X, 16, MKey, 0, 16);
            System.out.println("SKey: " + convertBytesToHex(SKey));
            System.out.println("MKey: " + convertBytesToHex(MKey));
            handshake = true;
            System.out.println("安全信道已建立，双方可以进行通信!");
        }
    }
}
