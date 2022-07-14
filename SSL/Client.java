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

class Message {
    byte MessageType;
    short length;
    byte[] body;

    public Message(byte MessageType, short length, byte[] body) {
        this.MessageType = MessageType;
        this.length = length;
        this.body = new byte[length];
        System.arraycopy(body, 0, this.body, 0, length);
    }

    public byte[] Data() {
        byte[] data = new byte[3 + body.length];
        data[0] = this.MessageType;
        byte[] len = new byte[2];
        len[0] = (byte) (this.length >> 8);
        len[1] = (byte) (this.length & 0xff);
        System.arraycopy(len, 0, data, 1, 2);
        System.arraycopy(this.body, 0, data, 3, this.length);
        return data;
    }
}

class Record {
    byte MessageType;
    short length;
    byte[] encryptedData;
    byte[] dataMAC = new byte[8];

    public Record(byte MessageType, short length, byte[] encryptedData, byte[] dataMAC) {
        this.MessageType = MessageType;
        this.length = length;
        this.encryptedData = new byte[length - 8];
        System.arraycopy(encryptedData, 0, this.encryptedData, 0, length - 8);
        System.arraycopy(dataMAC, 0, this.dataMAC, 0, 8);
    }

    public byte[] Data() {
        byte[] data = new byte[3 + this.length];
        data[0] = this.MessageType;
        byte[] len = new byte[2];
        len[0] = (byte) (this.length >> 8);
        len[1] = (byte) (this.length & 0xff);
        System.arraycopy(len, 0, data, 1, 2);
        System.arraycopy(this.encryptedData, 0, data, 3, this.length - 8);
        System.arraycopy(this.dataMAC, 0, data, 3 + this.length - 8, 8);
        return data;
    }
}

public class Client {
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
    static int flag = 3;
    static RSAPublicKey client_PublicKey;
    static RSAPrivateKey client_PrivateKey;
    static String client_publicKeyString, client_privateKeyString;
    static byte[] cpublicKey, cprivateKey;
    static byte[] clienthello = new byte[32];
    static byte[] serverhello = new byte[32];
    static byte[] Seq = new byte[16];
    static byte error;
    static boolean jump = false;
    byte[] cipherSuite = new byte[]{(byte) 0x01, (byte) 0x00};
    byte[] s_certificate;
    byte[] master_secret = new byte[48];
    byte[] encryptedSharedSecret;
    byte[] sign;
    byte[] SKey = new byte[16];
    byte[] MKey = new byte[16];
    static int error_num=0;

    public static void main(String[] args) throws Exception {
        //建立连接
        InetAddress serverAddress = InetAddress.getByName("localhost");
        DatagramSocket clientSocket = new DatagramSocket(1234);
        int serverSocket = 4321;

        Client client = new Client();

        while (true) {
            client.ClientHello(serverAddress, clientSocket, serverSocket);

            while (!handshake) {
                byte[] ReceiveData = new byte[200];
                DatagramPacket receivePacket = new DatagramPacket(ReceiveData, ReceiveData.length);
                clientSocket.receive(receivePacket);

                if (ReceiveData[0] == server_hello && connection) {
                    client.save_serverhello(serverAddress, clientSocket, serverSocket, ReceiveData);
                    System.arraycopy(clienthello, 0, Seq, 0, 8);
                    System.arraycopy(serverhello, 0, Seq, 8, 8);
                } else if (ReceiveData[0] == server_certificate && connection) {
                    client.ClientCertificate(serverAddress, clientSocket, serverSocket);
                    client.save_s_certificate(ReceiveData);
                    client.CertificateVerify(serverAddress, clientSocket, serverSocket);
                    client.ClientKeyExchange(serverAddress, clientSocket, serverSocket);
                } else if (ReceiveData[0] == server_finished && connection) {
                    client.SFinished_Verify(serverAddress, clientSocket, serverSocket, ReceiveData);
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
                        System.out.println("ClientCerttificateError!");
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
                    client.Send(serverAddress, clientSocket, serverSocket);

                    byte[] ReceiveData = new byte[200];
                    DatagramPacket receivePacket = new DatagramPacket(ReceiveData, ReceiveData.length);
                    clientSocket.receive(receivePacket);
                    client.Receive(serverAddress, clientSocket, serverSocket, ReceiveData);

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
        client_PublicKey = (RSAPublicKey) keyPair.getPublic();
        client_PrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        client_publicKeyString = encryptBASE64(client_PublicKey.getEncoded());
        client_privateKeyString = encryptBASE64(client_PrivateKey.getEncoded());
        cpublicKey = decryptBASE64(client_publicKeyString);
        cprivateKey = decryptBASE64(client_privateKeyString);
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

    public void Send(InetAddress serverAddress, DatagramSocket clientSocket, int serverSocket) throws Exception {
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
        DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, serverAddress, serverSocket);
        clientSocket.send(sendPacket);
        //System.out.println("消息已发送: " + convertBytesToHex(SendData));
        System.out.println("消息已发送!");
    }

    public void Receive(InetAddress serverAddress, DatagramSocket clientSocket, int serverSocket, byte[] ReceiveData) throws Exception {
        if (ReceiveData[0] == error_message) {
            flag--;
            System.out.println("对方校验错误次数："+(3-flag));
        } else {
            byte[] encryptedData = new byte[16];
            System.arraycopy(ReceiveData, 3, encryptedData, 0, 16);

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
            System.arraycopy(ReceiveData, 3 + encryptedData.length, rev_dataMAC, 0, 8);

            if (!Arrays.equals(dataMAC, rev_dataMAC)) {
                flag--;
                System.out.println("RecordError!");
                byte[] RE = new byte[]{(byte) 0x09};
                Message m = new Message(error_message, (short) RE.length, RE);
                byte[] SendData = m.Data();
                DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, serverAddress, serverSocket);
                clientSocket.send(sendPacket);
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

    public void ClientHello(InetAddress serverAddress, DatagramSocket clientSocket, int serverSocket) throws Exception {
        byte[] ch_msg = new byte[34];

        new SecureRandom().nextBytes(clienthello);
        System.arraycopy(clienthello, 0, ch_msg, 0, clienthello.length);
        System.arraycopy(cipherSuite, 0, ch_msg, 32, cipherSuite.length);

        Message m = new Message(client_hello, (short) ch_msg.length, ch_msg);
        byte[] SendData = m.Data();
        DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, serverAddress, serverSocket);
        clientSocket.send(sendPacket);
        //System.out.println("ClientHello: " + convertBytesToHex(SendData));
        System.out.println("ClientHello");
    }

    public void save_serverhello(InetAddress serverAddress, DatagramSocket clientSocket, int serverSocket, byte[] ReceiveData) throws Exception {
        if (ReceiveData[35] == cipherSuite[0] && ReceiveData[36] == cipherSuite[1]) {
            System.arraycopy(ReceiveData, 3, serverhello, 0, 32);
        } else {
            //System.out.println("ServerCiperSuiteError!");
            connection = false;
            byte[] SCSE = new byte[]{(byte) 0x02};
            error=SCSE[0];
            error_num++;
            Message m = new Message(error_message, (short) SCSE.length, SCSE);
            byte[] SendData = m.Data();
            DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, serverAddress, serverSocket);
            clientSocket.send(sendPacket);
            System.out.println("ERROR: " + convertBytesToHex(SendData));
        }
    }

    public void ClientCertificate(InetAddress serverAddress, DatagramSocket clientSocket, int serverSocket) throws Exception {
        genKeyPair();
        Message m = new Message(client_certificate, (short) cpublicKey.length, cpublicKey);
        byte[] SendData = m.Data();
        DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, serverAddress, serverSocket);
        clientSocket.send(sendPacket);
        //System.out.println("ClientCertificate: " + convertBytesToHex(SendData));
        System.out.println("ClientCertificate");
    }

    public void save_s_certificate(byte[] ReceiveData) {
        s_certificate = new byte[162];
        System.arraycopy(ReceiveData, 3, s_certificate, 0, 162);
    }

    public void CertificateVerify(InetAddress serverAddress, DatagramSocket clientSocket, int serverSocket) throws Exception {
        byte[] msg = new byte[clienthello.length + serverhello.length + s_certificate.length];
        System.arraycopy(clienthello, 0, msg, 0, clienthello.length);
        System.arraycopy(serverhello, 0, msg, clienthello.length, serverhello.length);
        System.arraycopy(s_certificate, 0, msg, (clienthello.length + serverhello.length), s_certificate.length);

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(client_PrivateKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        Signature signature = Signature.getInstance("Sha1withRSA");
        signature.initSign(privateKey);
        signature.update(msg);
        sign = signature.sign();
        Message m = new Message(certificate_verify, (short) sign.length, sign);
        byte[] SendData = m.Data();
        DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, serverAddress, serverSocket);
        clientSocket.send(sendPacket);
        //System.out.println("CertificateVerify: " + convertBytesToHex(SendData));
        System.out.println("CertificateVerify");
    }

    public void ClientKeyExchange(InetAddress serverAddress, DatagramSocket clientSocket, int serverSocket) throws Exception {
        new SecureRandom().nextBytes(master_secret);

        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(s_certificate));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        encryptedSharedSecret = cipher.doFinal(master_secret);
        Message m = new Message(client_key_exchange, (short) encryptedSharedSecret.length, encryptedSharedSecret);
        byte[] SendData = m.Data();
        DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, serverAddress, serverSocket);
        clientSocket.send(sendPacket);
        //System.out.println("master_secret: " + convertBytesToHex(master_secret));
        System.out.println("ClientKeyExchange");
    }

    public void SFinished_Verify(InetAddress serverAddress, DatagramSocket clientSocket, int serverSocket, byte[] ReceiveData) throws Exception {
        byte[] SF = new byte[32];
        System.arraycopy(ReceiveData, 3, SF, 0, 32);
        byte[] message_MAC;
        byte[] handshake_messages = new byte[384];
        System.arraycopy(clienthello, 0, handshake_messages, 0, clienthello.length);
        System.arraycopy(serverhello, 0, handshake_messages, clienthello.length, serverhello.length);
        int length1 = clienthello.length + serverhello.length;

        StringBuilder s = new StringBuilder();
        MessageDigest object = MessageDigest.getInstance("SHA-256");
        byte[] hash_sc = object.digest(s_certificate);
        byte[] hash_cc = object.digest(cpublicKey);

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

        if (!Arrays.equals(message_MAC, SF)) {
            //System.out.println("ServerHandshakeError!");
            connection = false;
            byte[] SHE = new byte[]{(byte) 0x08};
            error=SHE[0];
            error_num++;
            Message m = new Message(error_message, (short) SHE.length, SHE);
            byte[] SendData = m.Data();
            DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, serverAddress, serverSocket);
            clientSocket.send(sendPacket);
            System.out.println("ERROR:" + convertBytesToHex(SendData));
        } else {
            System.out.println("ServerFinished is true!");
            ClientFinished(serverAddress, clientSocket, serverSocket);

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

    public void ClientFinished(InetAddress serverAddress, DatagramSocket clientSocket, int serverSocket) throws Exception {
        byte[] message_MAC;
        byte[] handshake_messages = new byte[384];
        System.arraycopy(clienthello, 0, handshake_messages, 0, clienthello.length);
        System.arraycopy(serverhello, 0, handshake_messages, clienthello.length, serverhello.length);
        int length1 = clienthello.length + serverhello.length;

        StringBuilder s = new StringBuilder();
        MessageDigest object = MessageDigest.getInstance("SHA-256");
        byte[] hash_sc = object.digest(s_certificate);
        byte[] hash_cc = object.digest(cpublicKey);

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

        Message m = new Message(client_finished, (short) message_MAC.length, message_MAC);
        byte[] SendData = m.Data();
        DatagramPacket sendPacket = new DatagramPacket(SendData, SendData.length, serverAddress, serverSocket);
        clientSocket.send(sendPacket);
        //System.out.println("ClientFinished: " + convertBytesToHex(SendData));
        System.out.println("ClientFinished");
    }
}
