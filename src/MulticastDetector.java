import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Inet6Address;
import java.net.MulticastSocket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.swing.AbstractListModel;
import javax.swing.Timer;


public class MulticastDetector extends AbstractListModel<String> implements Runnable, ActionListener {
	private static final long serialVersionUID = -8646735687230911853L;
	
	private List<Node> nodes = new ArrayList<Node>();
	private MulticastSocket socket;
	private ChatServer server;
	private Inet6Address ip;
	private int port;
	
	public MulticastDetector(ChatServer server, Inet6Address ip, int port) throws IOException {
		this.server = server;
		this.ip = ip;
		this.port = port;
		socket = new MulticastSocket(port);
		socket.setReuseAddress(true);
		socket.joinGroup(ip);
		new Thread(this).start();
		new Timer(2500, this).start();
		new Timer(100, new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				for (int i = 0; i < nodes.size(); i++)
					if (System.currentTimeMillis() - nodes.get(i).last_beacon > 10000)
						nodes.remove(i--);
				fireContentsChanged(this, 0, nodes.size());
			}
		}).start();
	}

	@Override
	public String getElementAt(int index) {
		return nodes.get(index).long_string();
	}

	@Override
	public int getSize() {
		return nodes.size();
	}

	@Override
	public void run() {
		byte[] buf = new byte[65535];
		DatagramPacket packet = new DatagramPacket(buf, buf.length);
		while (true) {
			try {
				socket.receive(packet);
				Node node = new Node();
				node.address = (Inet6Address) packet.getAddress();
				node.port = packet.getPort();
				
				KeyFactory kf = KeyFactory.getInstance("ECMQV");
				X509EncodedKeySpec x509ks = new X509EncodedKeySpec(packet.getData());
				node.public_key = kf.generatePublic(x509ks);

				if (node.public_key.equals(server.node().public_key))
					continue;
				
				int index = nodes.indexOf(node);
				if (index != -1) {
					node = nodes.get(index);
				} else {
					nodes.add(node);
					index = nodes.indexOf(node);
				}
				node.last_beacon = System.currentTimeMillis();
				
				fireContentsChanged(this, index, index);
			} catch (IOException e) {
				System.err.println("Failed to receive a packet.");
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				System.err.println("Beacon contains invalid key.");
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public void actionPerformed(ActionEvent event) {
		byte[] data = server.node().public_key.getEncoded();
		
		DatagramPacket packet = new DatagramPacket(data, data.length, ip, port);
		try {
			server.send(packet);
		} catch (IOException e) {
			System.err.println("Failed to broadcast.");
			e.printStackTrace();
		}
	}

	public Node getNode(int index) {
		return nodes.get(index);
	}
	
	public Node getNode(Node node) {
		int index = nodes.indexOf(node);
		return index != -1 ? nodes.get(index) : null;
	}
}
