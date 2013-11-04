
import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.net.Inet6Address;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Santo implements Runnable {
	private MulticastDetector nodes;
	private ChatServer server;
	private JTabbedPane tabs;
	public static Santo instance;
	
	public Santo() {
		try {
			server = new ChatServer();
			nodes = new MulticastDetector(server, (Inet6Address)Inet6Address.getByName("ff0e::114"), 55555);
			server.setNodes(nodes);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}
		
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		instance = new Santo();
		SwingUtilities.invokeLater(instance);
	}

	@Override
	public void run() {
        final JFrame f = new JFrame("Santo");
        f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        tabs = new JTabbedPane(JTabbedPane.TOP);
        f.add(tabs);
        
        JPanel servers = new JPanel(new BorderLayout());
        tabs.add("Servers", servers);
        
        final JList<String> list = new JList<String>(nodes);
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setLayoutOrientation(JList.VERTICAL);
        list.setVisibleRowCount(-1);
        servers.add(list, BorderLayout.CENTER);
        
        JButton button = new JButton("Connect");
        button.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				int index = list.getSelectedIndex();
				if (index == -1)
					return;
				try {
					Node node = nodes.getNode(index);
					if (node.chat == null) {
						node.chat = new Chat(server, node);
						tabs.add(node.chat, node.short_string());
						server.connect(node);
					}
					tabs.setSelectedComponent(node.chat);
				} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | IOException e1) {
					System.err.println("Failed to establish a shared secret.");
					e1.printStackTrace();
				}
			}
        });
        servers.add(button, BorderLayout.PAGE_END); 
        
        f.pack();
        f.setVisible(true);
	}

	public void received(Node node, byte[] data) {
		if (node.chat == null) {
			node.chat = new Chat(server, node);
			node.chat.receive(data);
			tabs.add(node.chat, node.short_string());
		}
		tabs.setSelectedComponent(node.chat);
	}
}
