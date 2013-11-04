import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;


@SuppressWarnings("serial")
public class Chat extends JPanel implements ActionListener {
	private JTextPane textpane;
	private JScrollPane scrollpane;
	private JTextField entry;
	private Node node;
	private ChatServer server;
	
	public Chat(ChatServer server, Node node) {
		super(new BorderLayout());
		this.node = node;
		this.server = server;
		textpane = new JTextPane();
		textpane.setEditable(false);
		scrollpane = new JScrollPane(textpane);
		add(scrollpane, BorderLayout.CENTER);
		entry = new JTextField();
		add(entry, BorderLayout.PAGE_END);
		entry.addActionListener(this);
	}

	public void receive(byte[] data) {
		final String message = new String(data);
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				textpane.setText(textpane.getText()+"< "+message+"\n");				
			}
		});
	}

	@Override
	public void actionPerformed(final ActionEvent event) {
		try {
			server.send(node, event.getActionCommand().getBytes());
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | IOException e) {
			System.err.println("Failed to send message.");
			e.printStackTrace();
		}
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				textpane.setText(textpane.getText()+"> "+event.getActionCommand()+"\n");
				((JTextField)event.getSource()).setText("");
				scrollpane.getVerticalScrollBar().setValue(scrollpane.getVerticalScrollBar().getMaximum());
			}
		});
	}
}
