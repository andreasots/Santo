import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet6Address;
import java.net.SocketException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.spec.MQVPrivateKeySpec;
import org.bouncycastle.jce.spec.MQVPublicKeySpec;


public class ChatServer implements Runnable {
	private DatagramSocket socket;
	private Node node;
	private KeyPair keys;
	private MulticastDetector nodes;
	
	public ChatServer() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SocketException {
		socket = new DatagramSocket(0);
		System.out.printf("Listening on port %d\n", socket.getLocalPort());
		ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("secp521r1");
		KeyPairGenerator generator = KeyPairGenerator.getInstance("ECMQV");
		generator.initialize(ecParamSpec, new SecureRandom());
		keys = generator.generateKeyPair();
		
		node = new Node();
		node.address = (Inet6Address) socket.getInetAddress();
		node.port = socket.getLocalPort();
		node.public_key = keys.getPublic();
		
		new Thread(this).start();
	}
	
	public void setNodes(MulticastDetector nodes) {
		this.nodes = nodes; 
	}
	
	public void send(DatagramPacket packet) throws IOException {
		socket.send(packet);
	}
	
	public void send(Node node2, byte[] message) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, node2.symmetric_key);
		byte[] iv = cipher.getIV();
		assert(iv.length == 16);
		byte[] enc = cipher.doFinal(message);
		byte[] data = new byte[iv.length+enc.length];
		System.arraycopy(iv, 0, data, 0, iv.length);
		System.arraycopy(enc, 0, data, iv.length, enc.length);
		send(new DatagramPacket(data, data.length, node2.address, node2.port));
	}
	
	public Node node() {
		return node;
	}

	@Override
	public void run() {
		byte[] buf = new byte[65535];
		DatagramPacket packet = new DatagramPacket(buf, buf.length);
		while (true) {
			try {
				socket.receive(packet);
			} catch (Exception e) {
				System.err.println("Failed to receive a data packet.");
				e.printStackTrace();
				continue;
			}
			Node node2 = new Node();
			node2.address = (Inet6Address) packet.getAddress();
			node2.port = packet.getPort();
			node2 = nodes.getNode(node2);
			if (node == null) {
				System.err.println("Received a packet from unknown node.");
				continue;
			}
			if (node2.symmetric_key == null) {
				try {
					KeyFactory kf = KeyFactory.getInstance("ECMQV");
					X509EncodedKeySpec x509ks = new X509EncodedKeySpec(packet.getData());
					key_agreement(node2, kf.generatePublic(x509ks));
				} catch (Exception e) {
					System.err.println("Failed to establish a shared secret.");
					e.printStackTrace();
					continue;
				}
			} else {
				try {
					byte[] iv = new byte[16];
					System.arraycopy(packet.getData(), 0, iv, 0, iv.length);
					IvParameterSpec ivSpec = new IvParameterSpec(iv);
					Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
					cipher.init(Cipher.DECRYPT_MODE, node2.symmetric_key, ivSpec);
					byte[] data = cipher.doFinal(packet.getData(), 16, packet.getLength()-16);
					if (node2.chat != null)
						node2.chat.receive(data);
					Santo.instance.received(node2, data);
				} catch (Exception e) {
					System.err.println("Failed to decrypt a data packet.");
					e.printStackTrace();
					continue;
				}
			}
		}
	}

	public void connect(Node node2) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
		if (node2.symmetric_key != null)
			return;
		if (node2.ephemeral_keys == null) {
			ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("secp521r1");
			KeyPairGenerator generator = KeyPairGenerator.getInstance("ECMQV");
			generator.initialize(ecParamSpec, new SecureRandom());
			node2.ephemeral_keys = generator.generateKeyPair();
		}
		byte[] data = node2.ephemeral_keys.getPublic().getEncoded();
		send(new DatagramPacket(data, data.length, node2.address, node2.port));
	}
	
	public void key_agreement(Node node2, PublicKey ephemeral) throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {
		if (node2.ephemeral_keys == null)
			connect(node2);
		KeyAgreement ecmqv = KeyAgreement.getInstance("ECMQV");
		ecmqv.init(new MQVPrivateKeySpec(keys.getPrivate(), node2.ephemeral_keys.getPrivate(), node2.ephemeral_keys.getPublic()));
		ecmqv.doPhase(new MQVPublicKeySpec(node2.public_key, ephemeral), true);
		byte[] secret = MessageDigest.getInstance("SHA256").digest(ecmqv.generateSecret());
		node2.symmetric_key = new SecretKeySpec(secret, "AES");
		try {
			send(node2, "Connection established".getBytes());
		} catch (BadPaddingException | NoSuchPaddingException | IllegalBlockSizeException e) {
			e.printStackTrace();
		}
	}
}
